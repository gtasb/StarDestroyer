"""Job runner. Spawned detached; writes the exit code and state marker itself.

Kept as a separate file so the job survives the agent process: the parent only
calls Popen and forgets, the runner owns completion bookkeeping.
"""

import pathlib
import subprocess
import sys


def main() -> int:
    job_dir = pathlib.Path(sys.argv[1])
    command = sys.argv[2]
    cwd = sys.argv[3] if len(sys.argv) > 3 else None

    # Futex/timeouts aside, this is the only place that touches the shell, so
    # quoting differs by platform in exactly one spot.
    proc = subprocess.run(command, shell=True, cwd=cwd)
    (job_dir / "exit").write_text(str(proc.returncode))
    (job_dir / "state").write_text("done")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
