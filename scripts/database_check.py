"""Future separately authorized target check; never supplies credentials in arguments."""
import sys
import argparse
import json
from la.app import parser, execute

if __name__ == '__main__':
    # The common CLI owns containment, authority, target config, environment-name
    # handling and separate immutable receipts. No alternate credentials path.
    p=argparse.ArgumentParser()
    p.add_argument('--root',default='.la-runs'); p.add_argument('--bundle',required=True)
    p.add_argument('--authorized',action='store_true'); p.add_argument('--authority')
    p.add_argument('--target-config'); p.add_argument('--dsn-env',default='LA_TEST_DATABASE_DSN')
    args=p.parse_args()
    argv=['--root',args.root,'database-check',args.bundle,'--dsn-env',args.dsn_env]
    if args.authorized: argv.append('--authorized')
    if args.authority: argv.extend(['--authority',args.authority])
    if args.target_config: argv.extend(['--target-config',args.target_config])
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args(argv)))
    except (ValueError,OSError,KeyError,TypeError) as exc:
        raise SystemExit('database-check: '+type(exc).__name__) from None
