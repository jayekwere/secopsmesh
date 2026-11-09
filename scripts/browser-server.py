"""Owned local services for Playwright acceptance tests."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from secopsmesh.cli import initialize

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo import wait_ready  # noqa: E402

os.chdir(Path(__file__).resolve().parents[1])
initialize(Path(".runtime"))
children = []


def stop(*_):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    for command in ["lab", "executor", "serve"]:
        children.append(subprocess.Popen([sys.executable, "-m", "secopsmesh.cli", command]))  # noqa: S603 -- fixed project-owned entry point
        wait_ready(
            "http://127.0.0.1:" + {"lab": "8091", "executor": "8082", "serve": "8080"}[command]
        )
    wait_ready("http://127.0.0.1:8080")
    wait_ready("http://127.0.0.1:8091")
    wait_ready("http://127.0.0.1:8082")
    subprocess.run(
        [sys.executable, "-m", "secopsmesh.cli", "seed"], check=True, stdout=subprocess.DEVNULL
    )  # noqa: S603 -- fixed project-owned seed command
    while True:
        time.sleep(1)
finally:
    for process in children:
        process.terminate()
    for process in children:
        process.wait(timeout=5)
