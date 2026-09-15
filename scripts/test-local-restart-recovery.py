#!/usr/bin/env python3
"""Exercise restart-smoke failure reporting without starting validator nodes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tests/e2e/run-local-restart-recovery.sh"


class RestartRecoveryFailureTests(unittest.TestCase):
    def run_failure(self, missing_binary=False):
        with tempfile.TemporaryDirectory(prefix="restart-report-test-") as temporary:
            root = Path(temporary)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            artifacts = root / "artifacts"
            artifacts.mkdir()
            mktemp = mock_bin / "mktemp"
            mktemp.write_text(
                '#!/usr/bin/env bash\n'
                'exec /usr/bin/mktemp -d "$TEST_ARTIFACT_ROOT/run-XXXXXX"\n'
            )
            mktemp.chmod(0o755)
            node = mock_bin / "node"
            if not missing_binary:
                node.write_text("#!/usr/bin/env bash\nexit 23\n")
                node.chmod(0o755)
            result = subprocess.run(
                ["bash", str(SCRIPT)],
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}{os.pathsep}{os.environ['PATH']}",
                    "NODE_BIN": str(node),
                    "TEST_ARTIFACT_ROOT": str(artifacts),
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 1 if missing_binary else 23)
            self.assertNotIn("ALL CHECKS PASSED", result.stdout)
            self.assertIn("FAILED", result.stdout)
            runs = list(artifacts.iterdir())
            self.assertEqual(len(runs), 1)
            self.assertFalse((runs[0] / "password.txt").exists())
            self.assertFalse((runs[0] / "node1-validator.json").exists())
            self.assertFalse((runs[0] / "node2-validator.json").exists())
            if not missing_binary:
                self.assertTrue((runs[0] / "key1.log").is_file())

    def test_unexpected_key_generation_failure(self):
        self.run_failure()

    def test_explicit_preflight_failure(self):
        self.run_failure(missing_binary=True)


if __name__ == "__main__":
    unittest.main()
