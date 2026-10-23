"""Executable evaluator orchestration SOURCE; never imported/executed in Dirty Mode.

Adapters are injected by the evaluator operator. They must not capture oracle state
or bypass the provided request gateway. Python callbacks are not a security sandbox;
heldout eligibility also requires real external account/ACL evidence.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from time import perf_counter
from typing import Callable
from statistics import median
import hashlib

from .artifacts import CaptureStore, canonical, digest, is_sha
from .benchmark import ARMS, SimulatedSME
from .scorer import aggregate_variant_reports, score, score_product, slot_diagnostics


@dataclass(frozen=True)
class BatchCase:
    batch_id: str
    visible: dict
    oracle: list[dict]


@dataclass(frozen=True)
class VariantCase:
    variant_id: str
    split: str
    edition: str
    visible: dict
    batches: tuple[BatchCase, ...]
    # Evaluator-controlled policy; never passed to any inference/provider port.
    accepted_choices: dict[str, str]
    expected_layout: list[dict] | None = None


@dataclass(frozen=True)
class RunnerPorts:
    heuristic: Callable[[dict], dict]
    candidates: Callable[[dict, 'RequestGateway'], dict]
    questions: Callable[[dict], list[dict]]
    mapping: Callable[[dict, dict, list[dict]], dict]
    validate_mapping: Callable[[dict, dict], dict]
    transform: Callable[[dict, dict], list[dict]]
    provider: Callable[[dict], dict] | None = None
    count_tokens: Callable[[str], int] | None = None
    # Receives only producer artifacts/authority; returns concrete committed
    # readback wire observations. Independent oracle is never passed to it.
    target_observer: Callable[[dict, dict], dict] | None = None


def _visible(value: dict) -> dict:
    """Reject accidentally supplied evaluator keys before crossing a port."""
    allowed = {'schema_version', 'source_sha256', 'source_hex', 'framing_sha256',
               'record_refs', 'record_count', 'brief', 'permitted_samples',
               'sample_policy_sha256', 'batch_manifest', 'encoding', 'width'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError('visible input contains unknown/evaluator-only keys')
    return deepcopy(value)


def _prompt_input(visible: dict) -> dict:
    """Provider sees only the separate permitted artifact, never arbitrary file rows."""
    samples = visible.get('permitted_samples', {})
    allowed = {'schema_version', 'source_sha256', 'framing_sha256', 'authorization',
               'records', 'artifact_sha256'}
    if not isinstance(samples, dict) or set(samples) - allowed:
        raise ValueError('unknown/evaluator-only sample artifact fields')
    records = samples.get('records', samples.get('samples', []))
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError('permitted sample cap exceeded')
    authorization = samples.get('authorization')
    if (not is_sha(samples.get('artifact_sha256')) or not isinstance(authorization, str)
            or not authorization.strip() or len(authorization) > 1000):
        raise ValueError('hashed authorized permitted-samples artifact required')
    body = {key: value for key, value in samples.items() if key != 'artifact_sha256'}
    if digest(body) != samples['artifact_sha256']:
        raise ValueError('permitted-samples artifact hash mismatch')
    if samples.get('source_sha256') != visible.get('source_sha256'):
        raise ValueError('sample source mismatch')
    source = bytes.fromhex(visible.get('source_hex', ''))
    if hashlib.sha256(source).hexdigest() != visible.get('source_sha256'):
        raise ValueError('sample preflight requires exact visible source bytes')
    refs = {ref['ordinal']: ref for ref in visible.get('record_refs', [])}
    seen = set()
    for sample in records:
        if (not isinstance(sample, dict) or set(sample) - {'ordinal', 'raw_hex', 'raw_sha256',
                'source_sha256', 'framing_sha256', 'byte_start', 'length'}):
            raise ValueError('only explicitly authorized whole-record sample wire supported')
        ordinal = sample.get('ordinal')
        if type(ordinal) is not int or ordinal in seen or ordinal not in refs:
            raise ValueError('unknown/duplicate permitted sample ordinal')
        seen.add(ordinal)
        ref = refs[ordinal]
        if any(sample[key] != ref.get(key) for key in ('source_sha256', 'framing_sha256', 'byte_start', 'length')
               if key in sample):
            raise ValueError('sample identity mismatch')
        start, length = ref['byte_start'], ref['length']
        raw = source[start:start + length]
        if type(start) is not int or type(length) is not int or start < 0 or length < 1 or len(raw) != length:
            raise ValueError('sample byte range invalid')
        if (raw.hex() != sample.get('raw_hex') or hashlib.sha256(raw).hexdigest() != sample.get('raw_sha256')
                or ref.get('raw_sha256') != sample.get('raw_sha256')):
            raise ValueError('sample bytes/hash mismatch')
    brief = visible.get('brief', '')
    if not isinstance(brief, str) or len(brief) > 4000:
        raise ValueError('brief cap exceeded')
    return {'brief': brief, 'permitted_samples': deepcopy(samples),
            'source_sha256': visible.get('source_sha256')}


def _authorize(mode: str, case: VariantCase, authority: dict | None,
               freeze: dict | None, custody: dict | None, pins: dict, *, eligibility=None,
               store: CaptureStore | None = None) -> None:
    if mode not in ('rules', 'mock', 'live'):
        raise ValueError('use replay_archive for offline replay')
    if case.split not in ('development', 'validation', 'heldout'):
        raise ValueError('unknown split')
    if mode == 'live' and case.split != 'heldout':
        from .public_live import PublicLiveContext
        if type(eligibility) is not PublicLiveContext or store is None or freeze is not None:
            raise ValueError('pre-T2 public live requires exact T1 context, not a hidden freeze/custody flag')
        eligibility.authorize_case(case, pins, store, mode)
        return
    if mode == 'live' or case.split == 'heldout':
        from .edition_registry import EligibilityContext
        if type(eligibility) is not EligibilityContext or store is None:
            raise ValueError('verified observation receipts and exact edition registry required; custody booleans rejected')
        if freeze != eligibility.freeze:
            raise ValueError('runtime freeze differs from registered T2')
        eligibility.authorize_case(case, pins, store, mode)


class RequestGateway:
    """Single-flight, no retry; record attempts before invoking the provider.

    Paid usage accounting/reservation remains the provider adapter's responsibility.
    Unknown liability stops subsequent requests; reported costs are never invented.
    """

    def __init__(self, method: str, mode: str, visible: dict, ports: RunnerPorts,
                 store: CaptureStore, authority: dict | None, meter=None):
        self.method, self.mode, self.visible = method, mode, visible
        self.ports, self.store, self.authority = ports, store, authority or {}
        self.attempts: list[dict] = []
        self.busy = False
        self.meter = meter

    def request(self, purpose: str, candidates: list[dict] | None = None) -> object:
        if self.busy or len(self.attempts) >= ARMS[self.method]['max_requests']:
            raise ValueError('request budget/single-flight violation')
        if any(item.get('cost_status') == 'unknown' for item in self.attempts):
            raise ValueError('unknown liability: no automatic further request')
        if self.ports.provider is None:
            raise ValueError('provider port unavailable; no silent fallback')
        prompt = {'purpose': purpose, 'input': _prompt_input(self.visible)}
        if candidates is not None:
            if self.method == 'B1':
                raise ValueError('B1 cannot receive finite-candidate assistance')
            prompt['candidates'] = [{key: deepcopy(value) for key, value in item.items()
                                     if key in ('id', 'start', 'end', 'semantic_target', 'data_type', 'policy')}
                                    for item in candidates]
        text = canonical(prompt).decode('utf-8')
        if len(text.encode('utf-8')) > 32768:
            raise ValueError('prompt byte cap exceeded')
        tokens = self.ports.count_tokens(text) if self.ports.count_tokens else None
        if tokens is not None and (type(tokens) is not int or not 0 <= tokens <= 8000):
            raise ValueError('input token cap exceeded')
        if self.mode == 'live' and (tokens is None or not is_sha(self.authority.get('spend_authority_sha256'))):
            raise ValueError('live requires token preflight and spend authority')
        request = {'mode': self.mode, 'method': self.method, 'attempt': len(self.attempts) + 1,
                   'prompt': prompt, 'prompt_sha256': digest(prompt),
                   'max_input_tokens': 8000, 'max_output_tokens': 2000,
                   'allow_retries': False, 'allow_repairs': False if self.method == 'B1' else True}
        call_id = self.meter.reserve(request, tokens) if self.meter is not None else None
        settled = False
        item = {'attempt': request['attempt'], 'prompt_sha256': request['prompt_sha256'],
                'input_tokens_preflight': tokens, 'status': 'attempted',
                'cost_status': 'unknown', 'known_cost': None, 'usage': None}
        self.attempts.append(item)
        item['request_capture'] = self.store.put('provider_request', request)
        self.busy = True
        start = perf_counter()
        try:
            reply = self.ports.provider(deepcopy(request))
            item['raw_capture'] = self.store.put('provider_reply', reply)
            if not isinstance(reply, dict) or 'output' not in reply:
                raise ValueError('malformed provider envelope')
            usage = reply.get('usage')
            item['usage'] = usage
            if usage is not None:
                if not isinstance(usage, dict):
                    raise ValueError('invalid usage categories')
                for name in ('input_tokens', 'output_tokens'):
                    count = usage.get(name)
                    if count is not None and (type(count) is not int or count < 0):
                        raise ValueError('invalid usage token count')
                if usage.get('input_tokens', 0) > 8000 or usage.get('output_tokens', 0) > 2000:
                    raise ValueError('observed token cap exceeded')
            cost = reply.get('known_cost')
            if reply.get('cost_status') == 'known' and cost is not None:
                amount = Decimal(str(cost))
                if not amount.is_finite() or amount < 0:
                    raise ValueError('invalid cost')
                item.update(cost_status='known', known_cost=str(amount))
            if self.meter is not None:
                usage_receipt = self.meter.settle(call_id, reply=reply)
                settled = True
                item.update(usage_receipt)
                if usage_receipt['cost_status'] != 'known':
                    raise ValueError('T1 model/price/usage mismatch or unknown liability; future calls refused')
            item.update(status='returned', provider=reply.get('provider'), model=reply.get('model'),
                        price_sha256=reply.get('price_sha256'))
            return deepcopy(reply['output'])
        except Exception as exc:
            if self.meter is not None and not settled:
                self.meter.settle(call_id, error_type=type(exc).__name__)
            item.update(status='failed', error_type=type(exc).__name__)
            # Exception messages may contain DSNs/keys from external adapters.
            raise
        finally:
            item['latency_seconds'] = perf_counter() - start
            self.busy = False


def _questions(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError('questions must be a list')
    if len(value) > 12:
        raise ValueError('question budget exceeded; do not silently truncate')
    seen = set()
    for question in value:
        if not isinstance(question, dict) or not isinstance(question.get('id'), str):
            raise ValueError('invalid question')
        if question['id'] in seen:
            raise ValueError('duplicate question identity')
        seen.add(question['id'])
        allowed = {'id', 'kind', 'source_sha256', 'generation_sha256', 'dependency_sha256',
                   'candidate_ids', 'options', 'evidence', 'prompt', 'schema_version'}
        if set(question) - allowed:
            raise ValueError('question contains arbitrary broker query fields')
        offered = question.get('options', [])
        ids = [option.get('id') if isinstance(option, dict) else option for option in offered]
        if any(not isinstance(option, str) for option in ids) or len(ids) != len(set(ids)) or 'unknown' not in ids:
            raise ValueError('unique offered IDs and unknown required')
    return deepcopy(value)


def run_variant(case: VariantCase, ports: RunnerPorts, store: CaptureStore, *,
                mode: str = 'mock', pins: dict | None = None,
                authority: dict | None = None, freeze: dict | None = None,
                custody: dict | None = None, _suite_ref: dict | None = None,
                eligibility=None, target_ports=None, target_freeze_sha256: str | None = None) -> dict:
    """All five arms; failures stay in every denominator and raw attempts survive.

    One mapping/question session per layout, followed by all ten batches. Caller
    validates/seals corpus cardinality before an eligible full benchmark suite.
    This function records construction outcomes; product acceptance stays pending.
    """
    pins = pins or {}
    _authorize(mode, case, authority, freeze, custody, pins, eligibility=eligibility, store=store)
    if mode == 'live' or case.split == 'heldout':
        authority = eligibility.request_authority()
    if case.split == 'heldout':
        if _suite_ref is None:
            raise ValueError('heldout variants must be part of one predeclared full suite')
        declaration = store.get(_suite_ref, kind='suite_declaration')
        if (declaration.get('edition') != case.edition or declaration.get('freeze') != freeze
                or len(declaration.get('variants', [])) != 8
                or not any(item['id'] == case.variant_id and item['visible_sha256'] == digest(case.visible)
                           and item['oracle_sha256'] == digest([row for batch in case.batches for row in batch.oracle])
                           for item in declaration.get('variants', []))):
            raise ValueError('variant differs from suite declaration')
    visible = _visible(case.visible)
    if not case.batches or len({batch.batch_id for batch in case.batches}) != len(case.batches):
        raise ValueError('nonempty unique batches required')
    oracle = [row for batch in case.batches for row in deepcopy(batch.oracle)]
    # Validate oracle independently before calling any untrusted inference port.
    score(oracle, [], edition=case.edition)
    input_sha = digest(visible)
    results = []
    for method in ARMS:
        # Recheck registry revocation/exposure and exact pins before every arm.
        _authorize(mode, case, authority, freeze, custody, pins, eligibility=eligibility, store=store)
        if mode == 'live' or case.split == 'heldout':
            eligibility.claim_arm(case.variant_id, method)
        from .public_live import PublicLiveContext
        public_live = type(eligibility) is PublicLiveContext and mode == 'live'
        gateway = RequestGateway(method, mode, deepcopy(visible), ports, store, authority,
                                 meter=eligibility.meter(case, method) if public_live else None)
        started = perf_counter()
        raw, outputs, answers, questions = [], [], [], []
        mapping, status, error_type = None, 'completed', None
        generation = {}
        try:
            if method == 'B0':
                proposal = ports.heuristic(deepcopy(visible))
            elif method == 'B1':
                proposal = gateway.request('single_pass_full_mapping')
            else:
                generation = ports.candidates(deepcopy(visible), gateway)
                raw.append(store.put('generation', generation))
                if method != 'C0':
                    questions = _questions(ports.questions(deepcopy(generation)))
                    if public_live and len(questions) > eligibility.validate()['caps']['max_questions']:
                        raise ValueError('signed T1 question cap exceeded')
                if method == 'R1':
                    broker = SimulatedSME(deepcopy(case.accepted_choices))
                    answers = [broker.answer(question) for question in questions]
                proposal = ports.mapping(deepcopy(visible), deepcopy(generation), deepcopy(answers))
            raw.append(store.put('mapping_proposal', proposal))
            mapping = ports.validate_mapping(deepcopy(proposal), deepcopy(visible))
            if not isinstance(mapping, dict):
                raise ValueError('mapping validator must return validated dictionary')
            if mapping.get('mapping_status', mapping.get('status')) != 'complete':
                status = 'abstained'
            else:
                for batch in case.batches:
                    try:
                        outcome = ports.transform(_visible(batch.visible), deepcopy(mapping))
                        raw.append(store.put('batch_output', {'batch_id': batch.batch_id, 'outcomes': outcome}))
                        if not isinstance(outcome, list) or any(not isinstance(row, dict) for row in outcome):
                            raise ValueError('malformed row outcomes')
                        outputs.extend(outcome)
                    except Exception as exc:
                        status, error_type = 'failed', type(exc).__name__
                        raw.append(store.put('batch_failure', {'batch_id': batch.batch_id, 'error_type': error_type}))
            if method == 'B1' and len(gateway.attempts) != 1:
                raise ValueError('B1 requires exactly one attempt')
        except Exception as exc:
            status, error_type = 'failed', type(exc).__name__
        # Producer wire values are typed only using its mapping, never gold types.
        try:
            report = score_product(oracle, outputs, mapping or {}, edition=case.edition)
        except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation):
            report = score(oracle, [], edition=case.edition)
            status, error_type = 'failed', 'MalformedOutcomes'
        if status == 'completed':
            if not outputs:
                status = 'failed'
                error_type = 'NoOutput'
            elif report['row_parity'] != 'exact':
                status = 'partial'
        diagnostics = None
        if case.expected_layout is not None and mapping:
            try:
                diagnostics = slot_diagnostics(case.expected_layout, mapping.get('fields', []),
                                                generation.get('candidates', []))
            except (KeyError, ValueError, TypeError):
                diagnostics = {'status': 'malformed_layout', 'diagnostic_only': True}
        target_report = {'target_validation': 'not_run', 'batches': []}
        if target_ports is not None and mapping and status in ('completed', 'partial'):
            from .target_runner import run_target_arm
            selected_target_pin = target_freeze_sha256 or (freeze or {}).get('freeze_sha256')
            if public_live:
                plan_pin = eligibility.validate()['authority_sha256']
                target_report = run_target_arm(case, mapping, method, store, target_ports,
                    freeze_sha256=None, mode=mode,
                    phase_scope={'evaluation_phase': 'T1', 'split': case.split,
                                 'evaluation_plan_sha256': plan_pin, 'freeze_sha256': None},
                    preflight=lambda: _authorize(mode, case, authority, freeze, custody, pins,
                                                 eligibility=eligibility, store=store))
            elif eligibility is not None and selected_target_pin != eligibility.freeze['freeze_sha256']:
                raise ValueError('target scope differs from frozen protected suite')
            else:
                target_report = run_target_arm(case, mapping, method, store, target_ports,
                    freeze_sha256=selected_target_pin, mode=mode,
                    preflight=lambda: _authorize(mode, case, authority, freeze, custody, pins,
                                                 eligibility=eligibility, store=store))
        raw.append(store.put('arm_raw', {'method': method, 'input_sha256': input_sha,
                   'mapping': mapping, 'outcomes': outputs, 'questions': questions,
                   'answers': answers, 'attempts': gateway.attempts,
                   'status': status, 'error_type': error_type}))
        unknown = [item['attempt'] for item in gateway.attempts if item['cost_status'] != 'known']
        known = sum((Decimal(item['known_cost']) for item in gateway.attempts
                     if item['known_cost'] is not None), Decimal(0))
        result = {'schema_version': 1, 'method': method, 'variant_id': case.variant_id,
                  'edition': case.edition, 'split': case.split, 'mode': mode,
                  'evaluation_phase': 'T1' if public_live else 'T3' if case.split == 'heldout' else 'public',
                  'visibility': eligibility.catalog['visibility'] if public_live else 'sealed' if case.split == 'heldout' else 'public',
                  'status': status, 'error_type': error_type, 'input_sha256': input_sha,
                  'layout_diagnostics': diagnostics,
                  'score': report, 'captures': raw, 'request_attempts': len(gateway.attempts),
                  'failed_attempts': sum(item['status'] == 'failed' for item in gateway.attempts),
                  'usage': [item['usage'] for item in gateway.attempts],
                  'questions_asked': len(questions),
                  'questions_answered': sum(answer['option_id'] != 'unknown' for answer in answers),
                  'answer_source': 'agent_provisional' if method == 'R1' else None,
                  'known_cost_subtotal': str(known), 'known_total_cost': None if unknown else str(known),
                  'unknown_liabilities': unknown, 'latency_seconds': perf_counter() - started,
                  'target_validation': target_report['target_validation'], 'target_report': target_report,
                  'product_acceptance': 'pending'}
        result['receipt_capture'] = store.put('arm_receipt', result)
        if mode == 'live' or case.split == 'heldout':
            eligibility.finish_arm(case.variant_id, method, status, result['receipt_capture'])
            eligibility.authorize_case(case, pins, store, mode)
        results.append(result)
    manifest = {'schema_version': 1, 'edition': case.edition, 'variant_id': case.variant_id,
                'split': case.split, 'mode': mode, 'input_sha256': input_sha,
                'oracle_commitment_sha256': digest(oracle), 'pins': pins,
                'freeze_sha256': freeze.get('freeze_sha256') if freeze else None,
                'results': results, 'product_acceptance': 'pending'}
    return {**manifest, 'manifest_capture': store.put('variant_manifest', manifest)}


def run_suite(cases: list[VariantCase], ports: RunnerPorts, store: CaptureStore, *,
              split: str, mode: str = 'mock', pins: dict | None = None,
              authority: dict | None = None, freeze: dict | None = None,
              custody: dict | None = None, eligibility=None,
              attempt_request_id: str | None = None, expected_registry_head: str | None = None,
              target_ports=None, target_freeze_sha256: str | None = None) -> dict:
    """Predeclare the complete supported split before any arm sees an input.

    Failed arms remain in manifests. A failed/cancelled hidden suite cannot reuse
    its edition: the append-only registered attempt is retained even on crash.
    """
    expected = {'development': 6, 'validation': 4, 'heldout': 8}.get(split)
    from .public_live import PublicLiveContext
    public_live = mode == 'live' and type(eligibility) is PublicLiveContext
    if public_live and split in ('development', 'validation'):
        expected = len(eligibility.catalog['variants'])
    if expected is None or len(cases) != expected or len({case.variant_id for case in cases}) != expected:
        raise ValueError('complete 6/4/8 variant split required')
    if len({case.edition for case in cases}) != 1 or any(case.split != split for case in cases):
        raise ValueError('one edition/split required')
    for case in cases:
        if len(case.batches) != 10 or any(len(batch.oracle) != 100 for batch in case.batches):
            raise ValueError('each variant requires ten 100-record batches')
        malformed = sum(row['expected_outcome'] == 'quarantined' for batch in case.batches for row in batch.oracle)
        if not 20 <= malformed <= 50:
            raise ValueError('sealed 2–5 percent malformed stratum required per variant')
        if mode != 'live' and split != 'heldout':
            _authorize(mode, case, authority, freeze, custody, pins or {})
    protected = mode == 'live' or split == 'heldout'
    if protected:
        from .edition_registry import EligibilityContext
        from .eligibility import variant_identity
        if type(eligibility) not in (EligibilityContext, PublicLiveContext) or not attempt_request_id:
            raise ValueError('exact registered eligibility context and attempt request required')
        eligibility.validate()
        if public_live:
            if split == 'heldout' or freeze is not None or (pins or {}) != eligibility.pins:
                raise ValueError('T1 authority cannot authorize T2/T3 or stale provisional configuration')
            declared = {item['variant_id']: item for item in eligibility.catalog['variants']}
        else:
            if freeze != eligibility.freeze or (pins or {}) != eligibility.freeze['pins']:
                raise ValueError('mixed frozen suite configurations')
            declared = {item['variant_id']: item for item in eligibility.commitment['variants']}
        if mode != eligibility.suite['mode'] or [case.variant_id for case in cases] != eligibility.suite['variant_ids']:
            raise ValueError('wrong ordered declared suite')
        if any(variant_identity(case) != declared.get(case.variant_id) for case in cases):
            raise ValueError('actual source/sample/brief/oracle differs from T0')
        started = eligibility.begin(request_id=attempt_request_id, expected_head=expected_registry_head)
        if not started.newly_created:
            raise ValueError('historical attempt receipt returned; execution must not repeat')
    declaration = {'schema_version': 1, 'edition': cases[0].edition, 'split': split,
                   'mode': mode, 'variants': [{'id': case.variant_id,
                     'visible_sha256': digest(case.visible),
                     'oracle_sha256': digest([row for batch in case.batches for row in batch.oracle])}
                    for case in cases], 'freeze': freeze}
    predeclared = store.put('suite_declaration', declaration)
    try:
        manifests = [run_variant(case, ports, store, mode=mode, pins=pins,
                      authority=authority, freeze=freeze, custody=custody, _suite_ref=predeclared,
                      eligibility=eligibility, target_ports=target_ports,
                      target_freeze_sha256=target_freeze_sha256) for case in cases]
        report = {'schema_version': 1, 'declaration': predeclared,
                  'manifests': [item['manifest_capture'] for item in manifests],
                  'summary': summarize_suite(manifests)}
        capture = store.put('suite_report', report)
        if protected:
            statuses = [item['status'] for manifest in manifests for item in manifest['results']]
            no_output = all(item['score']['aggregates']['emitted_count'] == 0
                            for manifest in manifests for item in manifest['results'])
            terminal = ('no_output' if no_output else 'failed' if all(status == 'failed' for status in statuses)
                        else 'partial' if any(status != 'completed' for status in statuses) else 'completed')
            ending = eligibility.finish_suite(terminal, capture, request_id=attempt_request_id + ':finish')
            report['attempt_receipt'] = ending.capture
        return {**report, 'suite_capture': capture}
    except BaseException as exc:
        if protected:
            failure = store.put('suite_failure', {'schema_version': 1, 'edition': cases[0].edition,
                'attempt_id': eligibility.authority_receipt['payload']['attempt_id'] if public_live else eligibility.suite['attempt_id'],
                'error_type': type(exc).__name__,
                'declaration': predeclared})
            state = eligibility.registry.state(cases[0].edition)
            active = (state['t1']['attempts'].get(eligibility.authority_receipt['payload']['attempt_id'])
                      if public_live else state['attempt'])
            if active is not None and active['status'] == 'running':
                eligibility.finish_suite('cancelled' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed',
                    failure, request_id=attempt_request_id + ':failure')
        raise


def summarize_suite(manifests: list[dict]) -> dict:
    """Never pool rows before computing descriptive variant-level dispersion."""
    keys = [(item['edition'], item['variant_id']) for item in manifests]
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate variant manifest')
    methods = {}
    for method in ARMS:
        results = [next(result for result in item['results'] if result['method'] == method) for item in manifests]
        methods[method] = {**aggregate_variant_reports([result['score'] for result in results]),
                           'statuses': {name: sum(result['status'] == name for result in results)
                                        for name in ('completed', 'partial', 'abstained', 'failed')},
                           'questions_asked': sum(result['questions_asked'] for result in results),
                           'questions_answered': sum(result['questions_answered'] for result in results),
                           'request_attempts': sum(result['request_attempts'] for result in results),
                           'failed_attempts': sum(result['failed_attempts'] for result in results),
                           'known_cost_subtotal': str(sum((Decimal(result['known_cost_subtotal'])
                                                          for result in results), Decimal(0))),
                           'unknown_liabilities': sum(len(result['unknown_liabilities']) for result in results)}
        latencies = sorted(result['latency_seconds'] for result in results)
        methods[method]['latency_p50'] = median(latencies) if latencies else None
        methods[method]['latency_p95'] = latencies[max(0, (95 * len(latencies) + 99) // 100 - 1)] if latencies else None
        methods[method]['known_total_cost'] = (None if methods[method]['unknown_liabilities']
                                                else methods[method]['known_cost_subtotal'])
    hidden_complete = (len(manifests) == 8 and all(item['split'] == 'heldout' and item.get('freeze_sha256')
                          for item in manifests) and len({item['edition'] for item in manifests}) == 1
                          and len({item.get('freeze_sha256') for item in manifests}) == 1
                          and len({digest(item.get('pins')) for item in manifests}) == 1)
    r1 = methods['R1']
    target = (hidden_complete and (r1['semantic_rows']['rate'] or 0) >= .95
              and (r1['variant_rows']['min'] or 0) >= .90
              and not r1['statuses']['failed'])
    return {'schema_version': 1, 'methods': methods, 'variant_count': len(manifests),
            'benchmark_status': ('target_met' if target else 'reported_below_target') if hidden_complete else 'not_run',
            'product_acceptance': 'pending',
            'limitation': 'Descriptive source-run statistics; no custody/product acceptance inferred'}


def replay_archive(store: CaptureStore, manifest_ref: dict, oracle: list[dict], *,
                   retirement_ref: dict | None = None, registry=None) -> dict:
    """Rescore public or evaluator-retired captures; never calls inference/provider."""
    manifest = store.get(manifest_ref, kind='variant_manifest')
    if manifest['split'] == 'heldout':
        if retirement_ref is None:
            raise ValueError('active hidden capture cannot be replayed')
        retirement = store.get(retirement_ref, kind='retirement')
        if retirement['manifest_sha256'] != digest(manifest) or retirement['edition'] != manifest['edition']:
            raise ValueError('retirement does not bind this manifest')
        from .edition_registry import EditionRegistry
        if not isinstance(registry, EditionRegistry) or registry.store.root != store.root:
            raise ValueError('retired hidden replay requires the evaluator edition registry')
        state = registry.state(manifest['edition'])
        retirement_events = [event for event in registry.events() if event['edition'] == manifest['edition']
                             and event['event_type'] == 'retired']
        if (not state['retired'] or state['attempt'] is None or state['attempt']['status'] == 'running'
                or not any(event['event_sha256'] == retirement.get('registry_event_sha256') for event in retirement_events)
                or manifest.get('freeze_sha256') != state['freeze']['freeze_sha256']):
            raise ValueError('retirement journal/frozen attempt does not bind this replay')
    if digest(oracle) != manifest['oracle_commitment_sha256']:
        raise ValueError('replay oracle differs from sealed corpus')
    results = []
    for result in manifest['results']:
        captured = store.get(result['receipt_capture'], kind='arm_receipt')
        original = {key: value for key, value in result.items() if key != 'receipt_capture'}
        if captured != original:
            raise ValueError('arm receipt mismatch')
        raw_refs = [ref for ref in result['captures'] if ref['kind'] == 'arm_raw']
        if len(raw_refs) != 1:
            raise ValueError('one sealed raw output required')
        raw = store.get(raw_refs[0], kind='arm_raw')
        for reference in result['captures']:
            store.get(reference)
        try:
            rescored = score_product(oracle, raw['outcomes'], raw['mapping'] or {}, edition=manifest['edition'])
        except (ValueError, KeyError, TypeError, AttributeError, InvalidOperation):
            rescored = score(oracle, [], edition=manifest['edition'])
        results.append({'method': result['method'], 'original_status': result['status'],
                        'score': rescored, 'original_receipt': result['receipt_capture']})
    replay = {'schema_version': 1, 'mode': 'replay', 'edition': manifest['edition'],
              'manifest': manifest_ref, 'results': results,
              'stochastic_model_rerun': False, 'fresh_holdout': False,
              'target_validation': 'not_run', 'product_acceptance': 'pending'}
    return {**replay, 'replay_capture': store.put('replay_receipt', replay)}
