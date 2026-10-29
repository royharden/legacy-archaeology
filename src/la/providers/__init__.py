"""Advisory finite-ID ranking; explicit rules/mock/live modes never fall back."""
import json
from pathlib import Path
from la.contracts import canonical, digest

def rank(generation: dict, *, mode='rules', ledger_path=None, batch=None, brief=None,
         config=None, run=None, transport=None) -> dict:
    from la.contracts import validate_generation
    from la.providers.prompts import build_prompt, validate_ranking
    generation = validate_generation(generation)
    if digest({k:v for k,v in generation.items() if k!='generation_sha256'}) != generation['generation_sha256']:
        raise ValueError('invalid ranking generation identity')
    if mode not in ('rules', 'mock', 'live'):
        raise ValueError('explicit rules/mock/live mode required')
    if mode == 'live':
        if config is None or batch is None or brief is None or not ledger_path or not run:
            raise ValueError('live requires authority/config, exact permitted input and durable ledger')
        from la.providers.live import generate_once
        prompt = build_prompt(batch, brief, generation=generation)
        result = generate_once(prompt['text'], config, ledger_path, run=run, method='rank',
                               pins=prompt['pins'], transport=transport)
        status, selected = 'failed', {'ranked_candidate_ids': [], 'abstain': True}
        if result['text'] is not None:
            try:
                selected = validate_ranking(json.loads(result['text']), prompt['candidate_ids'])
                status = 'abstained' if selected['abstain'] else 'ranked'
            except (ValueError, TypeError):
                status = 'failed_invalid_ranking'
        receipt = dict(schema_version=1, mode=mode, generation_sha256=generation['generation_sha256'],
                       candidate_ids=selected['ranked_candidate_ids'], **selected,
                       attempts=result['receipt']['attempt'], status=status,
                       cost_known=result['receipt']['cost_known'],
                       known_cost_usd=result['receipt']['cost_usd'],
                       unknown_liability=not result['receipt']['cost_known'],
                       provider_receipt=result['receipt'], prompt_pins=prompt['pins'],
                       response_sha256=digest(result['text']), advisory_only=True)
        receipt['receipt_sha256'] = digest(receipt)
        return receipt
    # Stable evidence/ambiguity ranking, independent of model and option order.
    # Candidate evidence counts are observations, never proof of business meaning.
    priorities = {'balance': 0, 'effective_date': 1, 'account_ref': 2, 'status': 3, 'description': 4}
    candidates = sorted(generation['candidates'], key=lambda c: (
        priorities.get(c['semantic_target'], 5),
        -len({e.get('ordinal') for e in c['evidence']}), c['start'], c['end'], c['id']))
    ids = [c['id'] for c in candidates]
    receipt = {'schema_version':1, 'mode':mode,'generation_sha256':generation['generation_sha256'],
        'candidate_ids':ids, 'ranked_candidate_ids':ids, 'abstain':not ids, 'attempts':0,
        'cost_known':True,'known_cost_usd':'0','unknown_liability':False,'status':'offline',
        'ranking_policy':'consequence-then-evidence-span-id-v1', 'advisory_only':True,
        'mock_policy':'deterministic rules simulation' if mode=='mock' else None}
    receipt['receipt_sha256'] = digest(receipt)
    if ledger_path:
        path = Path(ledger_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Offline receipts do not become the paid-call authority.
        if path.suffix != '.jsonl': path = path.with_suffix('.offline.jsonl')
        with path.open('ab') as stream: stream.write(canonical(receipt)+b'\n')
    return receipt


def b1_mapping(batch, brief, config, ledger_path, *, run, validator=None, transport=None):
    """Separate exactly-one-attempt comparator; never used as product ranking."""
    from la.providers.prompts import build_prompt
    from la.providers.live import single_pass_mapping
    prompt = build_prompt(batch, brief, method='B1')
    return single_pass_mapping(prompt['text'], config, ledger_path, run=run,
                               pins=prompt['pins'], validator=validator, transport=transport)
