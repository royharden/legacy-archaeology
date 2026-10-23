"""Bounded offline bundle verification with explicit external-pin provenance.

No SQL, model, database, application entrypoint, or target driver is executed.
File bytes are read once into a bounded snapshot before schema/semantic checks.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from la.contracts import Approval, MappingSpec, MigrationBundle, RowOutcome, validate_batch, validate_generation
from la.review import build_mapping, canonical, digest, validate_event
from .provenance import LOAD_INSTRUCTIONS, producer_code_pin, verifier_code_pin

MIB = 1024 * 1024
MEMBER_LIMITS = {'manifest.json': 256 * 1024, 'source.json': 32 * MIB,
                 'mapping.json': 2 * MIB, 'rulings.json': 32 * MIB, 'inputs.json': 16 * MIB,
                 'schema.sql': 128 * 1024, 'migrate.sql': 16 * 1024,
                 'rows.jsonl': 32 * MIB, 'unresolved.jsonl': 16 * MIB,
                 'quarantine.jsonl': 32 * MIB, 'approval.json': 16 * 1024, 'LOAD.md': 16 * 1024}
TOTAL_LIMIT = 128 * MIB
REF_KEYS = ('source_sha256', 'framing_sha256', 'ordinal', 'byte_start', 'length', 'raw_sha256')


class BundleDifference(ValueError):
    def __init__(self, code, member=None, **details):
        self.difference = {'check': 'offline_bundle', 'code': code, **details}
        if member is not None: self.difference['member'] = member
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedSnapshot:
    manifest: dict
    batch: dict
    mapping: dict
    rows: list
    outcomes: list
    ddl: str
    sql: str
    columns: list
    member_sha256: dict
    code_matches: bool
    input_closure: bool


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _is_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _require_pins(value, member):
    for key, pin in value.items():
        if (key.endswith('_sha256') or key == 'generation_binding') and pin is not None and not _is_sha(pin):
            raise BundleDifference('invalid_identity_pin', member, dependency=key)


def _json(data, member):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise BundleDifference('duplicate_json_member', member, key=key[:80])
            result[key] = value
        return result
    def constant(_):
        raise BundleDifference('nonfinite_json_number', member)
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleDifference('invalid_json', member, error_type=type(exc).__name__) from exc


def _snapshot(bundle_path):
    given = Path(bundle_path).absolute()
    # A declared bundle root itself must not be a link/junction, nor traverse one.
    for item in (given, *given.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise BundleDifference('bundle_path_link_escape')
    root = given.resolve(strict=True)
    if not root.is_dir(): raise BundleDifference('bundle_not_directory')
    entries = []
    for entry in root.iterdir():
        entries.append(entry)
        if len(entries) > len(MEMBER_LIMITS): raise BundleDifference('member_count_limit')
    names = [entry.name for entry in entries]
    if len({name.casefold() for name in names}) != len(names):
        raise BundleDifference('duplicate_member_name')
    unexpected = sorted(set(names) - set(MEMBER_LIMITS))
    if unexpected: raise BundleDifference('unexpected_member', member=unexpected[0][:80])
    required = set(MEMBER_LIMITS) - {'inputs.json'}  # Pre-closure legacy bundles can be inspected, never loaded.
    if required - set(names): raise BundleDifference('missing_member', member=sorted(required - set(names))[0])
    content, total = {}, 0
    for entry in entries:
        metadata = entry.lstat()
        if entry.is_symlink() or (hasattr(entry, 'is_junction') and entry.is_junction()) or not stat.S_ISREG(metadata.st_mode) or entry.resolve(strict=True).parent != root:
            raise BundleDifference('member_path_escape', entry.name)
        if metadata.st_size > MEMBER_LIMITS[entry.name]: raise BundleDifference('member_size_limit', entry.name)
        total += metadata.st_size
        if total > TOTAL_LIMIT: raise BundleDifference('total_size_limit')
        with entry.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (metadata.st_dev, metadata.st_ino, metadata.st_size):
                raise BundleDifference('member_changed_before_read', entry.name)
            data = stream.read(MEMBER_LIMITS[entry.name] + 1)
            after = os.fstat(stream.fileno())
        if len(data) != metadata.st_size or (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise BundleDifference('member_changed_during_read', entry.name)
        content[entry.name] = data
    after_names = []
    for path in root.iterdir():
        after_names.append(path.name)
        if len(after_names) > len(MEMBER_LIMITS): raise BundleDifference('member_set_changed_during_read')
    if sorted(after_names) != sorted(names):
        raise BundleDifference('member_set_changed_during_read')
    return root, content


def _records_source(batch):
    records = batch['records']
    if len(records) > 10000: raise BundleDifference('record_count_limit', 'source.json')
    if batch['status'] != 'accepted': raise BundleDifference('source_not_accepted', 'source.json')
    intake = batch.get('intake') or batch['samples'].get('intake')
    if not isinstance(intake, dict): raise BundleDifference('framing_descriptor_missing', 'source.json')
    if intake.get('bounded_refusal') or intake.get('observed_record_count') != len(records) or intake.get('materialized_record_count') != len(records) or intake.get('unmaterialized_record_count') != 0:
        raise BundleDifference('source_accounting_mismatch', 'source.json')
    source = bytearray()
    separators = intake.get('separators', [])
    if len(separators) != len(records): raise BundleDifference('separator_cardinality', 'source.json')
    for ordinal, (record, separator) in enumerate(zip(records, separators)):
        raw = bytes.fromhex(record['raw_hex'])
        ending = bytes.fromhex(separator['raw_hex'])
        if record['ordinal'] != ordinal or record['byte_start'] != len(source) or len(raw) != record['length'] or _sha(raw) != record['raw_sha256']:
            raise BundleDifference('record_identity_mismatch', 'source.json', ordinal=ordinal)
        if record['source_sha256'] != batch['source_sha256'] or record['framing_sha256'] != batch['framing_sha256']:
            raise BundleDifference('record_dependency_mismatch', 'source.json', ordinal=ordinal)
        expected_ending = {'LF': b'\n', 'CRLF': b'\r\n'}.get(batch['framing'])
        if expected_ending is None or ending not in (expected_ending, b'') or (not ending and ordinal != len(records) - 1):
            raise BundleDifference('separator_policy_mismatch', 'source.json', ordinal=ordinal)
        if separator != {'ordinal': ordinal, 'byte_start': len(source) + len(raw), 'length': len(ending), 'raw_hex': ending.hex()}:
            raise BundleDifference('separator_reference_mismatch', 'source.json', ordinal=ordinal)
        source.extend(raw); source.extend(ending)
        if len(source) > 5 * MIB: raise BundleDifference('source_size_limit', 'source.json')
    from la.ingest.evidence import verify_records
    verify_records(batch, bytes(source))
    if _sha(source) != batch['source_sha256'] or intake.get('input_byte_count') != len(source):
        raise BundleDifference('source_reconstruction_mismatch', 'source.json')
    return bytes(source)


def _journal(lineage, generation):
    if not isinstance(lineage, dict) or set(lineage) != {'schema_version', 'generation', 'events'} or type(lineage['schema_version']) is not int or lineage['schema_version'] != 1:
        raise BundleDifference('invalid_ruling_envelope', 'rulings.json')
    events = lineage['events']
    if not isinstance(events, list) or len(events) > 10000: raise BundleDifference('event_count_limit', 'rulings.json')
    answers, ids, requests, chains = {}, set(), set(), {}
    previous_sequence = 0
    for exported in events:
        if not isinstance(exported, dict) or type(exported.get('sequence')) is not int or exported['sequence'] != previous_sequence + 1:
            raise BundleDifference('journal_sequence_mismatch', 'rulings.json')
        previous_sequence = exported['sequence']
        event = {k: v for k, v in exported.items() if k != 'sequence'}
        # Audit every historical event's hash/schema; current generation additionally
        # resolves offered choices/dependencies. Historical generations are not invented.
        from la.contracts import AnswerEvent
        event = AnswerEvent.model_validate(event).model_dump()
        _require_pins(event, 'rulings.json')
        if digest({k: v for k, v in event.items() if k != 'event_id'}) != event['event_id'] or event['event_id'] in ids or event['request_id'] in requests:
            raise BundleDifference('journal_event_identity_mismatch', 'rulings.json')
        ids.add(event['event_id']); requests.add(event['request_id'])
        chain_key = (event['generation_binding'], event['question_id'])
        prior = chains.get(chain_key)
        if event['revision'] != (prior['revision'] + 1 if prior else 1) or event['expected_revision'] != event['revision'] - 1 or event['previous_event_id'] != (prior['event_id'] if prior else None) or event['old_option_id'] != (prior['option_id'] if prior else None) or not event['actor'].strip() or not event['reason'].strip():
            raise BundleDifference('historical_journal_chain_mismatch', 'rulings.json')
        chains[chain_key] = event
        if event['generation_binding'] != digest(generation): continue
        event = validate_event(event, generation)
        old = answers.get(event['question_id'])
        if event['revision'] != (old['revision'] + 1 if old else 1) or event['previous_event_id'] != (old['event_id'] if old else None) or event['old_option_id'] != (old['option_id'] if old else None):
            raise BundleDifference('journal_chain_mismatch', 'rulings.json')
        answers[event['question_id']] = event
    return {'generation_binding': digest(generation), 'answers': answers}


def _outcome_file(data, filename):
    lines = data.splitlines()
    if len(lines) > 10000: raise BundleDifference('outcome_count_limit', filename)
    outcomes, seen = [], set()
    for line in lines:
        if not line: raise BundleDifference('blank_outcome_line', filename)
        row = RowOutcome.model_validate(_json(line, filename)).model_dump()
        identity = digest(row['record_ref'])
        if identity in seen: raise BundleDifference('duplicate_record_ref', filename, ordinal=row['record_ref']['ordinal'])
        seen.add(identity); outcomes.append(row)
    return outcomes


def inspect_snapshot(bundle_path):
    """Internal artifact snapshot for offline checks and the compatibility loader."""
    from . import approve_mapping, sql_artifacts, transform, validate_mapping
    root, files = _snapshot(bundle_path)
    raw_manifest = _json(files['manifest.json'], 'manifest.json')
    manifest = MigrationBundle.model_validate(raw_manifest).model_dump()
    _require_pins(manifest, 'manifest.json')
    if digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'}) != manifest['bundle_sha256']:
        raise BundleDifference('manifest_identity_mismatch', 'manifest.json')
    if set(manifest['files']) != set(files) - {'manifest.json'}:
        raise BundleDifference('referenced_member_set_mismatch', 'manifest.json')
    for name, expected in manifest['files'].items():
        if not _is_sha(expected) or _sha(files[name]) != expected:
            raise BundleDifference('artifact_hash_mismatch', name)
    batch = validate_batch(_json(files['source.json'], 'source.json'))
    _require_pins(batch, 'source.json')
    source = _records_source(batch)
    mapping = MappingSpec.model_validate(_json(files['mapping.json'], 'mapping.json')).model_dump()
    _require_pins(mapping, 'mapping.json')
    validate_mapping(batch, mapping, require_complete=True)
    approval = Approval.model_validate(_json(files['approval.json'], 'approval.json')).model_dump()
    if approval != approve_mapping(mapping, approval['actor'], approval['reason']):
        raise BundleDifference('approval_binding_mismatch', 'approval.json')
    lineage = _json(files['rulings.json'], 'rulings.json')
    generation = validate_generation(lineage['generation'])
    _require_pins(generation, 'rulings.json')
    projection = _journal(lineage, generation)
    if build_mapping(batch, generation, projection) != mapping:
        raise BundleDifference('mapping_ruling_lineage_mismatch', 'mapping.json')
    code_matches = manifest['producer_code_sha256'] == producer_code_pin()
    input_closure = False
    if 'inputs.json' in files:
        inputs = _json(files['inputs.json'], 'inputs.json')
        if not isinstance(inputs, dict) or set(inputs) != {'schema_version', 'brief', 'permitted_samples'} or type(inputs['schema_version']) is not int or inputs['schema_version'] != 1:
            raise BundleDifference('invalid_inputs_envelope', 'inputs.json')
        if inputs['brief'] is not None and inputs['permitted_samples'] is not None:
            if not isinstance(inputs['brief'], str) or len(inputs['brief']) > 4000 or not isinstance(inputs['permitted_samples'], dict):
                raise BundleDifference('invalid_input_types', 'inputs.json')
            from la.ingest import ingest_bytes
            declarations = batch['declared_format']
            rebuilt = ingest_bytes(source, inputs['brief'], inputs['permitted_samples'],
                                   declared_encoding=declarations['encoding'],
                                   declared_record_type=declarations['record_family'],
                                   declared_numeric=declarations['numeric'])
            if rebuilt != batch:
                raise BundleDifference('intake_config_sample_lineage_mismatch', 'source.json')
            input_closure = True
    for key, value in {'source_sha256': batch['source_sha256'], 'mapping_sha256': mapping['mapping_sha256'],
                       'generation_binding': mapping['generation_binding'], 'config_sha256': batch['config_sha256'],
                       'approval_sha256': approval['approval_sha256'], 'supporting_event_ids': mapping['supporting_event_ids']}.items():
        if manifest[key] != value: raise BundleDifference('manifest_dependency_mismatch', 'manifest.json', dependency=key)
    outcomes = transform(batch, mapping)
    counts, all_refs = {}, set()
    for kind, member in (('converted', 'rows.jsonl'), ('unresolved', 'unresolved.jsonl'), ('quarantined', 'quarantine.jsonl')):
        expected = [row for row in outcomes if row['outcome'] == kind]
        actual = _outcome_file(files[member], member)
        for row in actual:
            ref = digest(row['record_ref'])
            if ref in all_refs: raise BundleDifference('cross_outcome_duplicate_ref', member, ordinal=row['record_ref']['ordinal'])
            all_refs.add(ref)
        if actual != expected:
            raise BundleDifference('deterministic_outcome_mismatch', member, expected_count=len(expected), observed_count=len(actual))
        counts[kind] = len(actual)
    if counts != manifest['counts'] or manifest['record_count'] != len(outcomes) or sum(counts.values()) != len(batch['records']):
        raise BundleDifference('record_accounting_mismatch', 'manifest.json')
    status = 'complete' if outcomes and counts['converted'] == len(outcomes) else 'partial'
    if manifest['mapping_status'] != 'complete' or manifest['transformation_status'] != status or manifest['target_validation'] != 'not_run' or manifest['row_parity'] != 'not_run':
        raise BundleDifference('false_status_claim', 'manifest.json')
    ddl, sql, columns = sql_artifacts(mapping)
    if files['schema.sql'] != ddl.encode('utf-8') or files['migrate.sql'] != sql.encode('utf-8') or manifest['columns'] != columns:
        raise BundleDifference('deterministic_sql_mismatch', 'schema.sql/migrate.sql')
    if files['LOAD.md'] != LOAD_INSTRUCTIONS.encode('utf-8'):
        raise BundleDifference('deterministic_load_instructions_mismatch', 'LOAD.md')
    return VerifiedSnapshot(manifest, batch, mapping, [row for row in outcomes if row['outcome'] == 'converted'],
                            outcomes, ddl, sql, columns, {name: _sha(data) for name, data in files.items()},
                            code_matches, input_closure)


def verify_bundle(bundle_path, *, expected_bundle_sha256=None, expected_source_sha256=None,
                  expected_mapping_sha256=None):
    """Return a sealed offline audit; a self-consistent manifest is explicitly untrusted."""
    expected = {'bundle_sha256': expected_bundle_sha256, 'source_sha256': expected_source_sha256,
                'mapping_sha256': expected_mapping_sha256}
    result = {'schema_version': 1, 'operation': 'offline_bundle_verification',
              'expected_pins': expected, 'observed_pins': {},
              'pin_status': 'unverified' if any(v is not None for v in expected.values()) else 'missing',
              'pin_origin': 'caller_supplied' if any(v is not None for v in expected.values()) else 'manifest_only',
              'integrity_status': 'failed', 'differences': [], 'loadable': False,
              'target_authority_required': True, 'target_validation': 'not_run', 'row_parity': 'not_run',
              'product_acceptance': 'pending', 'verifier_code_sha256': verifier_code_pin()}
    invalid = [key for key, value in expected.items() if value is not None and not _is_sha(value)]
    if invalid:
        result['pin_status'] = 'invalid'
        result['differences'].append({'check': 'expected_pins', 'code': 'invalid_external_pin', 'keys': invalid})
    try:
        snapshot = inspect_snapshot(bundle_path)
        manifest = snapshot.manifest
        result['observed_pins'] = {key: manifest[key] for key in expected}
        mismatch = [key for key, value in expected.items() if value is not None and value != manifest[key]]
        if mismatch:
            result['pin_status'] = 'invalid' if invalid else 'mismatch'
            result['differences'].append({'check': 'expected_pins', 'code': 'external_pin_mismatch', 'keys': mismatch})
        elif not invalid:
            result['pin_status'] = 'matched' if expected_bundle_sha256 is not None else 'partial' if any(v is not None for v in expected.values()) else 'missing'
        result.update(integrity_status='verified', member_sha256=snapshot.member_sha256,
                      counts=manifest['counts'], record_count=manifest['record_count'],
                      producer_code_sha256=manifest['producer_code_sha256'], current_producer_code_sha256=producer_code_pin(),
                      mapping_status=manifest['mapping_status'], transformation_status=manifest['transformation_status'])
        if not snapshot.code_matches or result['current_producer_code_sha256'] != result['verifier_code_sha256']:
            result['differences'].append({'check': 'producer_code', 'code': 'current_code_mismatch'})
            result['integrity_status'] = 'incomplete'
        if not snapshot.input_closure:
            result['differences'].append({'check': 'source_lineage', 'code': 'original_inputs_not_embedded'})
            result['integrity_status'] = 'incomplete'
        if result['pin_status'] in ('missing', 'partial'):
            result['differences'].append({'check': 'expected_pins', 'code': 'external_bundle_pin_required'})
        result['loadable'] = result['integrity_status'] == 'verified' and result['pin_status'] == 'matched' and bool(snapshot.rows)
    except BundleDifference as exc:
        result['differences'].append(exc.difference)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        result['differences'].append({'check': 'offline_bundle', 'code': 'invalid_artifact', 'error_type': type(exc).__name__})
    result['verification_sha256'] = digest(result)
    return result


def write_verification_receipt(destination, receipt):
    """Exclusive atomic publication outside any frozen bundle; no bundle mutation."""
    if receipt.get('verification_sha256') != digest({k: v for k, v in receipt.items() if k != 'verification_sha256'}):
        raise ValueError('verification receipt identity mismatch')
    destination = Path(destination)
    if destination.is_symlink() or any((parent / 'manifest.json').is_file() for parent in destination.resolve().parents):
        raise ValueError('verification receipt must be outside frozen bundle')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.' + uuid.uuid4().hex + '.tmp')
    data = (canonical(receipt) + '\n').encode('utf-8')
    try:
        with temporary.open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {'path': str(destination), 'sha256': _sha(data), 'verification_sha256': receipt['verification_sha256']}
