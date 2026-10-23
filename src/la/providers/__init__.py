"""Offline provider port and append-only attempt ledger; live calls are disabled."""
import json
from pathlib import Path
from la.contracts import canonical, digest

def rank(generation: dict, *, mode='rules', ledger_path=None) -> dict:
    if mode not in ('rules', 'mock'):
        raise ValueError('live provider unavailable: model, prices, authority and cap unapproved')
    receipt = {'schema_version':1, 'mode':mode,'generation_sha256':generation['generation_sha256'],
        'candidate_ids':[c['id'] for c in generation['candidates']], 'attempts':0,
        'cost_known':True,'known_cost_usd':'0','unknown_liability':False,'status':'offline'}
    if ledger_path:
        path = Path(ledger_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('ab') as stream: stream.write(canonical(dict(receipt,receipt_sha256=digest(receipt)))+b'\n')
    return receipt
