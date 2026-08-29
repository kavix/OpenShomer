import subprocess
from typing import List, Tuple


class CommitManager:
    """Stages and commits patched files."""

    @staticmethod
    def commit_patch(files: List[str], message: str, cwd: str) -> Tuple[bool, str]:
        try:
            for f in files:
                subprocess.run(["git", "add", f], cwd=cwd, check=True)
            res = subprocess.run(
                ["git", "commit", "-m", message],
                cwd=cwd,
                capture_output=True,
                text=True
            )
            return res.returncode == 0, res.stdout or res.stderr
        except Exception as e:
            return False, str(e)
