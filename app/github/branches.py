import subprocess


class BranchManager:
    """Manages Git branch creation for security patches."""

    @staticmethod
    def create_security_branch(branch_name: str, cwd: str) -> tuple[bool, str]:
        try:
            res = subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=cwd,
                capture_output=True,
                text=True
            )
            if res.returncode == 0:
                return True, f"Created branch {branch_name}"
            return False, res.stderr
        except Exception as e:
            return False, str(e)
