"""A scripted APT host for tests that drive scans through the API.

``ScriptedHost`` answers the package-scan commands by kind, so a test chooses
what the repository refresh and the candidate listing return, and can change
them between scans to model failure and recovery.
"""

CLEAN_REFRESH = {
    "status": "success",
    "stdout": "Hit:1 http://deb.debian.org/debian trixie InRelease\n",
    "stderr": "",
    "exit_code": 0,
}
UNAUTHORIZED_REFRESH = {
    "status": "warning",
    "stdout": (
        "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
        "Err:2 https://enterprise.example.com/debian/pve trixie InRelease\n"
        "  401  Unauthorized [IP: 203.0.113.9 443]\n"
    ),
    "stderr": "E: Some index files failed to download.\n",
    "exit_code": 100,
}
INSTALLED = "openssl\t3.0.1\tinstall ok installed\ncurl\t7.0\tinstall ok installed\n"
LISTING = (
    "Listing...\n"
    "openssl/trixie-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"
    "curl/trixie 7.1 amd64 [upgradable from: 7.0]\n"
)


class ScriptedHost:
    def __init__(self):
        self.refresh = CLEAN_REFRESH
        self.listing = LISTING
        self.installed = INSTALLED
        self.calls = []

    def run(self, command):
        if "apt-get update" in command:
            return dict(self.refresh)
        if command.startswith("dpkg-query"):
            return {
                "status": "success",
                "stdout": self.installed,
                "stderr": "",
                "exit_code": 0,
            }
        if "apt list" in command:
            return {
                "status": "success",
                "stdout": self.listing,
                "stderr": "",
                "exit_code": 0,
            }
        raise AssertionError(f"unexpected command: {command}")

    def install(self, monkeypatch):
        host = self

        def execute(_ssh, system_id, command, timeout=None, user_id=None):
            host.calls.append((system_id, command, timeout, user_id))
            return host.run(command)

        for name in ("execute_command", "execute_privileged_command"):
            monkeypatch.setattr(f"app.services.ssh_service.SSHService.{name}", execute)
