import subprocess
import sys

# List of commands to execute for PR review checks
commands = [
    "cargo fmt -- --check",
    "cargo clippy -- -D warnings",
    "cargo test",
    "cargo doc --no-deps",
    "cargo audit",
    "cargo build"
]

# Execute each command
for command in commands:
    print(f'Running: {command}')
    process = subprocess.run(command, shell=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode != 0:
        print(f'Error executing {command}: {process.stderr}')
        sys.exit(1)
    else:
        print(process.stdout)

print('All checks passed successfully!')
