import pathlib
import sys
import time

time.sleep(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
pathlib.Path(sys.argv[2]).write_text("ALIVE")
