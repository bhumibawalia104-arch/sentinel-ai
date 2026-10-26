import os
import tempfile

# Use a throw-away database so tests never touch your real sentinel.db
os.environ["SENTINEL_DB_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db")
