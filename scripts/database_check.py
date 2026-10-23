"""Future separately authorized target check; never supplies credentials in arguments."""
import argparse
import json
from la.postgres import database_check

if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('--bundle',required=True)
    p.add_argument('--authorized',action='store_true')
    args=p.parse_args()
    print(json.dumps(database_check(args.bundle,authorized=args.authorized),indent=2))
