"""Repeatable keyless development suite; no hidden assets or live mode option.

python -m evaluation.public_check --out <new owned directory>
Product capabilities enter through the explicitly named ports factory only.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import importlib
import json
from pathlib import Path

from .artifacts import CaptureStore, digest
from .answer_policy import offered_policy_matches
from .corpus import build_development_variant, development_layouts, variant_case
from .runner import run_suite, replay_archive


def public_answers(case, ports):
    """Public evaluator SME: choose a matching *offered* policy, otherwise unknown.

    Matching uses the independently serialized layout, never a product decoder.
    This is disclosed extra information for R1; it is not autonomous inference.
    """
    class NoProvider:
        method = 'R1'
        def request(self, *args, **kwargs):
            raise ValueError('answer-policy construction cannot call a provider')
    generation = ports.candidates(case.visible, NoProvider())
    candidates = {item['id']: item for item in generation.get('candidates', [])}
    answer_policy = {}
    for question in ports.questions(generation):
        selected = 'unknown'
        for option in question['options']:
            candidate = candidates.get(option['id'])
            if candidate is None:
                continue
            if any(offered_policy_matches(candidate, field) for field in case.expected_layout or []):
                selected = option['id']
                break
        answer_policy[question['id']] = selected
    return replace(case, accepted_choices=answer_policy)


def run(out, *, factory='scripts.product_ports:factory'):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    captures = out / 'captures'
    captures.mkdir()
    store = CaptureStore(captures)
    module, symbol = factory.split(':', 1)
    ports = getattr(importlib.import_module(module), symbol)({
        'run': 'public-rv2-keyless', 'ledger_path': str(out / 'unused-offline-ledger.sqlite'),
        'use_ranker': False})
    cases = [variant_case(build_development_variant(layout['variant_id']))
             for layout in development_layouts()]
    cases = [public_answers(case, ports) for case in cases]
    report = run_suite(cases, ports, store, split='development', mode='mock',
                       pins={'public_check_sha256': digest(Path(__file__).read_text(encoding='utf-8'))})
    replays = []
    for case, manifest in zip(cases, report['manifests'], strict=True):
        oracle = [row for batch in case.batches for row in batch.oracle]
        replays.append(replay_archive(store, manifest, oracle))
    result = {'kind': 'public-development-validation', 'mode': 'mock', 'split': 'development',
              'provider': 'offline-simulation', 'live_b1': 'not_run',
              'holdout': 'not_run', 'product_acceptance': 'pending',
              'r1_answer_policy': 'agent_provisional; exact offered-policy match to public layout; missing option stays unknown',
              'suite': report, 'replays': replays,
              'limitation': 'Public development and deterministic replay only; failures remain in full denominators.'}
    (out / 'report.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, help='new evaluator-owned output directory')
    parser.add_argument('--ports', default='scripts.product_ports:factory')
    args = parser.parse_args()
    report = run(args.out, factory=args.ports)
    print(json.dumps(report['suite']['summary'], indent=2))


if __name__ == '__main__':
    main()
