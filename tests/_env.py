"""Imported first by every test: what tests do stays out of the real log and off the network."""

import os
import tempfile

os.environ["SD_LOG_DIR"] = os.path.join(tempfile.gettempdir(), "sd-test-logs")
os.environ["SCA_MAVEN"] = "0"
