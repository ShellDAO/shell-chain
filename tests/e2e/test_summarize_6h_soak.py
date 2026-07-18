#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize-6h-soak.py")
SPEC = importlib.util.spec_from_file_location("summarize_6h_soak", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class SoakSummaryPathTests(unittest.TestCase):
    def test_reads_regular_phase_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            (output_dir / "orchestrator.log").write_text(
                "PHASE_END name=smoke status=ok rc=0 duration_s=12 log=smoke.log\n"
            )

            phases = SUMMARY.read_phase_results(output_dir)

            self.assertEqual(phases[0]["name"], "smoke")

    def test_rejects_oversized_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "orchestrator.log"
            with path.open("wb") as log_file:
                log_file.truncate(SUMMARY.MAX_LOG_BYTES + 1)

            with self.assertRaisesRegex(ValueError, "exceeds"):
                SUMMARY.read_phase_results(Path(directory))

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symbolic links unavailable")
    def test_rejects_symbolic_link_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            target = output_dir / "target.log"
            target.write_text(
                "PHASE_END name=external status=ok rc=0 duration_s=1 log=x.log\n"
            )
            (output_dir / "orchestrator.log").symlink_to(target)

            with self.assertRaisesRegex(ValueError, "regular file"):
                SUMMARY.read_phase_results(output_dir)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symbolic links unavailable")
    def test_rejects_symbolic_link_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_output = root / "real"
            linked_output = root / "linked"
            real_output.mkdir()
            linked_output.symlink_to(real_output, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "real directory"):
                SUMMARY.validate_output_dir(linked_output)


if __name__ == "__main__":
    unittest.main()
