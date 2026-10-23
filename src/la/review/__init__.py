"""Bounded questions and transactional, replayable human ruling authority."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from la.contracts import AnswerEvent, MappingSpec, Question, validate_batch, validate_generation

REQUIRED = ('account_ref', 'description', 'balance', 'effective_date', 'status')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def binding(generation):
    validate_generation(generation)
    if digest({k: v for k, v in generation.items() if k != 'generation_sha256'}) != generation['generation_sha256']:
        raise ValueError('generation hash mismatch')
    ids = set()
    for candidate in generation['candidates']:
        if candidate['id'] in ids or digest({k: v for k, v in candidate.items() if k != 'id'}) != candidate['id']:
            raise ValueError('invalid or duplicate candidate identity')
        ids.add(candidate['id'])
    return digest(generation)


def questions(generation: dict, limit: int = 12) -> list[dict]:
    if not 0 <= limit <= 12:
        raise ValueError('question limit must be between 0 and 12')
    result = []
    for target in REQUIRED:
        offered = [c for c in generation['candidates'] if c['semantic_target'] == target]
        # Even singleton candidates require an explicit policy selection; heuristics are not facts.
        dependency = binding(generation)
        question_id = digest({'generation_binding': dependency, 'semantic_target': target})
        examples = [e for c in offered for e in c.get('evidence', [])][:6]
        result.append({'schema_version': 1, 'id': question_id, 'semantic_target': target,
                       'generation_binding': dependency, 'source_sha256': generation['source_sha256'],
                       'prompt': f'Which byte span and interpretation represents {target}? Select unknown if none is correct.',
                       'options': [{'id': c['id'], 'start': c['start'], 'end': c['end'],
                                    'data_type': c['data_type'], 'policy': c['policy']} for c in offered]
                                  + [{'id': 'unknown'}], 'evidence': examples})
    # Consequential numeric/date interpretations precede text labels, deterministically.
    result.sort(key=lambda q: (0 if q['semantic_target'] == 'balance' else 1 if q['semantic_target'] == 'effective_date' else 2, q['semantic_target']))
    return [Question.model_validate(question).model_dump() for question in result[:limit]]


class RulingStore:
    """SQLite is the only authority. JSONL exports are never imported as state."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS active (singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projection (binding TEXT NOT NULL, question_id TEXT NOT NULL, revision INTEGER NOT NULL, event_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(binding,question_id));
                CREATE TABLE IF NOT EXISTS receipts (request_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, binding TEXT NOT NULL, payload TEXT NOT NULL);
            ''')

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def bind_generation(self, generation: dict) -> dict:
        dependency = binding(generation)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO active VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET binding=excluded.binding', (dependency,))
        return {'generation_binding': dependency}

    def answer(self, generation: dict, question_id: str, option_id: str, actor: str,
               reason: str, expected_revision: int, request_id: str) -> dict:
        if not actor.strip() or not reason.strip() or not request_id.strip():
            raise ValueError('actor, reason and request_id are required')
        dependency = binding(generation)
        question = next((q for q in questions(generation) if q['id'] == question_id), None)
        if question is None or option_id not in {o['id'] for o in question['options']}:
            raise ValueError('question or offered option is invalid')
        request = {'generation_binding': dependency, 'question_id': question_id, 'option_id': option_id,
                   'actor': actor, 'reason': reason, 'expected_revision': expected_revision, 'request_id': request_id}
        request_hash = digest(request)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            active = db.execute('SELECT binding FROM active WHERE singleton=1').fetchone()
            if active is None or active[0] != dependency:
                raise ValueError('stale generation: bind the current generation before answering')
            prior = db.execute('SELECT request_hash,binding,payload FROM receipts WHERE request_id=?', (request_id,)).fetchone()
            if prior:
                if prior[0] != request_hash or prior[1] != dependency:
                    raise ValueError('request_id reused with different content')
                return json.loads(prior[2])
            old = db.execute('SELECT revision,event_id,payload FROM projection WHERE binding=? AND question_id=?', (dependency, question_id)).fetchone()
            revision = old[0] if old else 0
            if expected_revision != revision:
                raise ValueError(f'competing answer: expected revision {revision}')
            event = dict(request, schema_version=1, revision=revision + 1,
                         previous_event_id=old[1] if old else None,
                         old_option_id=json.loads(old[2])['option_id'] if old else None,
                         semantic_target=question['semantic_target'],
                         source_sha256=generation['source_sha256'],
                         generation_sha256=generation['generation_sha256'],
                         brief_sha256=generation['brief_sha256'], policy_sha256=generation['policy_sha256'],
                         timestamp=datetime.now(timezone.utc).isoformat())
            event['event_id'] = digest(event)
            event = AnswerEvent.model_validate(event).model_dump()
            cursor = db.execute('INSERT INTO events(event_id,payload) VALUES(?,?)', (event['event_id'], canonical(event)))
            receipt = {'schema_version': 1, 'event_id': event['event_id'], 'sequence': cursor.lastrowid,
                       'revision': revision + 1, 'generation_binding': dependency, 'request_id': request_id}
            db.execute('INSERT INTO projection VALUES(?,?,?,?,?) ON CONFLICT(binding,question_id) DO UPDATE SET revision=excluded.revision,event_id=excluded.event_id,payload=excluded.payload', (dependency, question_id, revision + 1, event['event_id'], canonical(event)))
            db.execute('INSERT INTO receipts VALUES(?,?,?,?)', (request_id, request_hash, dependency, canonical(receipt)))
        return receipt

    def events(self) -> list[dict]:
        with self._connection() as db:
            return [dict(json.loads(payload), sequence=sequence) for sequence, payload in db.execute('SELECT sequence,payload FROM events ORDER BY sequence')]

    def projection(self, generation: dict) -> dict:
        dependency = binding(generation)
        with self._connection() as db:
            active = db.execute('SELECT binding FROM active WHERE singleton=1').fetchone()
            if active is None or active[0] != dependency:
                raise ValueError('stale generation')
            answers = {q: json.loads(p) for q, p in db.execute('SELECT question_id,payload FROM projection WHERE binding=?', (dependency,))}
        return {'generation_binding': dependency, 'answers': answers}

    def replay(self, generation: dict) -> dict:
        """Rebuild a projection from the committed journal, never from JSONL."""
        dependency = binding(generation)
        # Perform current-generation check even when there are no matching events.
        self.projection(generation)
        answers = {}
        for event in self.events():
            event = AnswerEvent.model_validate({k: v for k, v in event.items() if k != 'sequence'}).model_dump()
            if event['generation_binding'] != dependency:
                continue
            content = {k: v for k, v in event.items() if k not in ('event_id', 'sequence')}
            if digest(content) != event['event_id']:
                raise ValueError('journal event hash mismatch')
            old = answers.get(event['question_id'])
            if event['revision'] != (old['revision'] + 1 if old else 1) or event['previous_event_id'] != (old['event_id'] if old else None):
                raise ValueError('journal revision chain mismatch')
            answers[event['question_id']] = {k: v for k, v in event.items() if k != 'sequence'}
        return {'generation_binding': dependency, 'answers': answers}

    def export(self, destination) -> dict:
        events = self.events()
        data = ''.join(canonical(event) + '\n' for event in events).encode('utf-8')
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create protects prior projections; callers choose a fresh path after a crash.
        with destination.open('xb') as stream:
            stream.write(data)
        return {'events': len(events), 'sha256': hashlib.sha256(data).hexdigest(), 'path': str(destination)}


def build_mapping(batch: dict, generation: dict, rulings) -> dict:
    batch = validate_batch(batch)
    projection = rulings.projection(generation) if isinstance(rulings, RulingStore) else rulings
    dependency = binding(generation)
    if projection.get('generation_binding') != dependency:
        raise ValueError('stale rulings')
    for key in ('source_sha256', 'framing_sha256', 'brief_sha256'):
        if batch[key] != generation[key]:
            raise ValueError(f'stale generation {key}')
    fields, event_ids, unresolved = [], [], []
    for q in questions(generation):
        event = projection.get('answers', {}).get(q['id'])
        candidate = next((c for c in generation['candidates'] if event and c['id'] == event['option_id'] and c['semantic_target'] == q['semantic_target']), None)
        if event is None or event.get('generation_binding') != dependency or candidate is None:
            unresolved.append(f"unresolved:{q['semantic_target']}")
            continue
        fields.append(candidate)
        event_ids.append(event['event_id'])
    covered = set()
    width = batch['width']
    for field in fields:
        start, end = field['start'], field['end']
        target = field['semantic_target']
        kind = 'decimal' if target == 'balance' else 'date' if target == 'effective_date' else 'text'
        policy = field['policy']
        if field['data_type'] != kind or not {'padding_byte', 'padding_side', 'trim', 'nullable'} <= policy.keys():
            unresolved.append(f'unresolved_policy:{target}')
        if kind == 'decimal' and not {'scale', 'precision', 'sign'} <= policy.keys():
            unresolved.append('unresolved_policy:balance')
        if kind == 'date' and ('format' not in policy or (policy['format'] == 'YYMMDD' and 'century_window' not in policy)):
            unresolved.append('unresolved_policy:effective_date')
        if width is None or not (0 <= start < end <= width):
            unresolved.append('span_out_of_range')
        span = set(range(start, end))
        if covered & span:
            unresolved.append('overlapping_fields')
        covered |= span
    filler = generation.get('filler', [])
    for item in filler:
        start, end = item['start'], item['end']
        span = set(range(start, end))
        if width is None or not 0 <= start < end <= width or covered & span:
            unresolved.append('invalid_filler')
        covered |= span
    if width is None:
        unresolved.append('record_width_unresolved')
    elif covered != set(range(width)):
        unresolved.append('uncovered_bytes:explicit_filler_required')
    if {f['semantic_target'] for f in fields} != set(REQUIRED) or len(fields) != len(REQUIRED):
        unresolved.append('required_semantic_fields')
    if batch['status'] != 'accepted':
        unresolved.append('batch_refused')
    mapping = {'schema_version': 1, 'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
               'generation_sha256': generation['generation_sha256'], 'generation_binding': dependency,
               'policy_sha256': generation['policy_sha256'], 'width': width, 'fields': fields, 'filler': filler,
               'supporting_event_ids': event_ids, 'mapping_status': 'incomplete' if unresolved else 'complete',
               'unresolved': sorted(set(unresolved))}
    mapping['mapping_sha256'] = digest(mapping)
    return MappingSpec.model_validate(mapping).model_dump()
