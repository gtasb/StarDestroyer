"""Job runner. Spawned detached; writes the exit code and state marker itself.

Kept as a separate file so the job survives the agent process: the parent only
calls Popen and forgets, the runner owns completion bookkeeping.
"""

import json
import pathlib
import subprocess
import sys


def main() -> int:
    job_dir = pathlib.Path(sys.argv[1])
    command = json.loads(sys.argv[2])
    cwd = sys.argv[3] if len(sys.argv) > 3 else None

    # A list never meets a shell. The log is passed on explicitly: a detached
    # runner has no console, and without this the child's output is lost.
    code = 127
    try:
        with (job_dir / "log").open("ab") as log:
            try:
                code = subprocess.run(command, shell=isinstance(command, str), cwd=cwd,
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log).returncode
            except OSError as exc:
                log.write(f"无法启动: {exc}\n".encode())
    finally:
        (job_dir / "exit").write_text(str(code))
        (job_dir / "state").write_text("done")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
