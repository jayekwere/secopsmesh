"""Generate disposable Compose credentials; never overwrites existing state."""

import json
import secrets
from pathlib import Path

from secopsmesh.cli import initialize
from secopsmesh.domain import canonical

directory = Path(".runtime/compose")
initialize(directory, lab_port=8080)
control = json.loads((directory / "config.json").read_text())
executor = json.loads((directory / "executor-config.json").read_text())
password = secrets.token_urlsafe(32)
database_url = "postgresql+psycopg://mesh:" + password + "@db:5432/mesh"
control["SECMESH_DATABASE_URL"] = executor["SECMESH_DATABASE_URL"] = database_url
control["SECMESH_EXECUTOR_URL"] = "http://executor:8080"
for values in [control, executor]:
    targets = json.loads(values["SECMESH_TARGETS"])
    targets["lab-host"]["url"] = "http://lab:8080"
    values["SECMESH_TARGETS"] = canonical(targets)
lab = {"SECMESH_LAB_KEY": executor.pop("SECMESH_LAB_KEY"), "SECMESH_LAB_DB": "/app/.runtime/lab.db"}
executor.pop("SECMESH_LAB_DB", None)
for name, values in [
    ("api", control),
    ("executor", executor),
    ("lab", lab),
    ("db", {"POSTGRES_USER": "mesh", "POSTGRES_PASSWORD": password, "POSTGRES_DB": "mesh"}),
]:
    path = directory / (name + ".env")
    if any("'" in str(value) or "\n" in str(value) for value in values.values()):
        raise ValueError("env value needs explicit escaping")
    path.write_text(
        "\n".join(key + "='" + str(value) + "'" for key, value in values.items()) + "\n"
    )
    path.chmod(0o600)
print("Generated disposable configuration in .runtime/compose; no credentials printed.")
