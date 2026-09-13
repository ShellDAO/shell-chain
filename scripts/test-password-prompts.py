#!/usr/bin/env python3
"""Check password confirmation with a real controlling terminal (Unix)."""

import errno
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


BINARY = str(Path(sys.argv[1]).resolve(strict=True))
TIMEOUT_SECONDS = 10


def command(output, allow_env):
    return [BINARY, *(["--allow-env-password"] if allow_env else []),
            "key", "generate", "--algorithm", "prompt-test", "--output", str(output)]


def environment(value):
    env = os.environ.copy()
    env.pop("SHELL_KEYSTORE_PASSWORD", None)
    if value is not None:
        env["SHELL_KEYSTORE_PASSWORD"] = value
    return env


def check_interactive(name, value, allow_env=True, matching=False):
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "unused.json"
        args = command(output, allow_env)
        env = environment(value)
        pid, terminal = pty.fork()
        if pid == 0:
            os.chdir(directory)
            os.execve(BINARY, args, env)
        transcript = bytearray()
        sent_first = sent_confirmation = False
        status = None
        try:
            deadline = time.monotonic() + TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.02)[0]:
                    try:
                        chunk = os.read(terminal, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        chunk = b""
                    transcript.extend(chunk)
                # Wait until rpassword has disabled terminal echo before typing.
                echo_disabled = not termios.tcgetattr(terminal)[3] & termios.ECHO
                if not sent_first and echo_disabled:
                    os.write(terminal, b"first synthetic value\n")
                    sent_first = True
                elif (sent_first and not sent_confirmation and echo_disabled
                      and b"Confirm password:" in transcript):
                    answer = b"first synthetic value\n" if matching else b"different synthetic value\n"
                    os.write(terminal, answer)
                    sent_confirmation = True
                done, status_code = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = status_code
                    while True:
                        try:
                            remaining = os.read(terminal, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                        if not remaining:
                            break
                        transcript.extend(remaining)
                    break
            assert status is not None, f"{name}: password prompt did not finish"
            assert sent_confirmation, f"{name}: interactive confirmation was skipped"
            assert b"Enter password for new keystore:" in transcript, f"{name}: initial prompt missing"
            expected = b"unsupported algorithm" if matching else b"Passwords do not match"
            assert expected in transcript, f"{name}: unexpected password validation outcome"
            assert os.waitstatus_to_exitcode(status) != 0, f"{name}: command unexpectedly succeeded"
            assert not output.exists(), f"{name}: test unexpectedly created a keystore"
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(terminal)
        print(f"PASS: {name}")


check_interactive("missing environment password", None)
check_interactive("empty environment password", "")
check_interactive("environment password requires opt-in", "synthetic environment value", allow_env=False)
check_interactive("matching fallback confirmation", None, matching=True)
with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "unused.json"
    result = subprocess.run(command(output, True), env=environment("synthetic environment value"),
                            cwd=directory, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=TIMEOUT_SECONDS, check=False)
    assert result.returncode != 0 and b"unsupported algorithm" in result.stderr
    assert b"Confirm password:" not in result.stderr
    assert not output.exists()
print("PASS: configured environment password stays non-interactive")
