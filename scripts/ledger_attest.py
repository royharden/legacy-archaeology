"""Explicit operator command: attest provider-ledger attempts for one evaluator call.

Produces the read-only T3-LIVE-API A1 `call_ledger_attestation` from an EXISTING
provider ledger (never a freshly created empty one) and stores it verbatim in an
existing evaluator CaptureStore, where a signed run_owner void receipt can cite it.
Mints no authority and voids nothing. No ledger/database access on import.
"""
import argparse
from pathlib import Path


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator-root',required=True)
    p.add_argument('--ledger',required=True,help='existing provider ledger relative to operator root')
    p.add_argument('--capture-root',required=True,help='existing evaluator CaptureStore relative to operator root')
    p.add_argument('--evaluation-phase',required=True,choices=['T1','T3'])
    p.add_argument('--evaluation-authority-sha256',required=True)
    p.add_argument('--gateway-prompt-sha256',required=True)
    p.add_argument('--source-sha256',required=True)
    p.add_argument('--evaluator-method',required=True,choices=['B1','C0','R0','R1'])
    return p


def execute(args):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from la.app.artifacts import within
    from la.providers.accounting import CallLedger
    from evaluation.artifacts import CaptureStore
    root=Path(args.operator_root).resolve(strict=True)
    # exists=True: CallLedger would otherwise create an empty ledger whose
    # attestation falsely shows "never sent".
    ledger=within(root,args.ledger,exists=True)
    if not ledger.is_file() or ledger.stat().st_size==0: raise ValueError('existing nonempty provider ledger required')
    store=CaptureStore(within(root,args.capture_root,exists=True))
    value=CallLedger(ledger).attempts_matching(evaluation_phase=args.evaluation_phase,
        evaluation_authority_sha256=args.evaluation_authority_sha256,
        gateway_prompt_sha256=args.gateway_prompt_sha256,source_sha256=args.source_sha256,
        evaluator_method=args.evaluator_method)
    return {'attestation':value,'capture':store.put('call_ledger_attestation',value),
            'voided':False,'authority_created':False}


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_ledger_attest: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()
