"""Issue a random credential into explicitly selected operator-owned configuration files."""

import argparse
import json
import secrets
from pathlib import Path

from secopsmesh.config import ROLES, token_hash
from secopsmesh.domain import SOURCES, canonical

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--config", type=Path, action="append", required=True)
parser.add_argument("--name", required=True)
parser.add_argument("--tenant", required=True)
parser.add_argument("--role", choices=sorted(ROLES), action="append", required=True)
parser.add_argument("--source", choices=SOURCES, action="append", default=[])
parser.add_argument("--instance", default="default")
parser.add_argument("--synthetic", action="store_true")
parser.add_argument("--token-file", type=Path, required=True)
args = parser.parse_args()
if args.token_file.exists():
    parser.error("refusing to overwrite a credential file")
if any(not 1 <= len(v) <= 128 for v in [args.name, args.tenant, args.instance]):
    parser.error("principal fields must contain 1..128 characters")
if "collector" in args.role and not args.source:
    parser.error("collector credentials require explicit sources")
prepared = []
token = secrets.token_urlsafe(32)
for config in args.config:
    values = json.loads(config.read_text())
    principals = json.loads(values["SECMESH_CREDENTIALS"])
    if any(p["name"] == args.name and p["tenant"] == args.tenant for p in principals.values()):
        parser.error(
            "principal already exists; rotate/revoke explicitly instead of duplicating authority"
        )
    principals[token_hash(token)] = {
        "name": args.name,
        "tenant": args.tenant,
        "roles": args.role,
        "sources": args.source,
        "instance": args.instance,
        "synthetic": args.synthetic,
    }
    values["SECMESH_CREDENTIALS"] = canonical(principals)
    prepared.append((config, values))
args.token_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
with args.token_file.open("x") as handle:
    handle.write(token + "\n")
args.token_file.chmod(0o600)
for config, values in prepared:
    staging = config.with_suffix(".new")
    staging.write_text(canonical(values) + "\n")
    staging.chmod(0o600)
    staging.replace(config)
print(
    "Credential written to the selected token file. Restart the selected services to load updated principal configuration."
)
