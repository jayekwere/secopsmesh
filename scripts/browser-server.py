"""Owned local services for Playwright acceptance tests."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from secopsmesh.cli import initialize

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo import wait_ready  # noqa: E402

os.chdir(Path(__file__).resolve().parents[1])
Path(".runtime").mkdir(exist_ok=True, mode=0o700)
temporary = tempfile.TemporaryDirectory(prefix="browser-", dir=".runtime")
directory = Path(temporary.name).resolve()
initialize(directory, api_port=18180, lab_port=18191, executor_port=18182)
pointer = Path(".runtime/e2e-session.json")
pointer.write_text(json.dumps({"token_file": str(directory / "tokens.json")}))
pointer.chmod(0o600)
children = []


def stop(*_):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    for command, port in [("lab", 18191), ("executor", 18182), ("serve", 18180)]:
        config = directory / ("config.json" if command == "serve" else "executor-config.json")
        children.append(
            subprocess.Popen(  # noqa: S603 -- fixed project-owned entry point and isolated test paths
                [
                    sys.executable,
                    "-m",
                    "secopsmesh.cli",
                    command,
                    "--config",
                    str(config),
                    "--port",
                    str(port),
                ]
            )
        )  # noqa: S603 -- fixed project-owned entry point and owned isolated test directory
        wait_ready(f"http://127.0.0.1:{port}")
    subprocess.run(  # noqa: S603 -- fixed project-owned seed command and temporary token path
        [
            sys.executable,
            "-m",
            "secopsmesh.cli",
            "seed",
            "--api",
            "http://127.0.0.1:18180",
            "--tokens",
            str(directory / "tokens.json"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )  # noqa: S603 -- fixed project-owned seed command
    while True:
        time.sleep(1)
finally:
    for process in children:
        process.terminate()
    for process in children:
        process.wait(timeout=5)
    temporary.cleanup()
