import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    bundle = Path(__file__).resolve().parent
    raise SystemExit(
        subprocess.call([sys.executable, "-m", "parquity", "replay", str(bundle)])
    )
