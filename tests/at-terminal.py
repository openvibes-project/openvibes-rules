"""Runs a command on a pseudo-terminal and answers its prompts as they appear.

Usage: python3 tests/at-terminal.py PROMPT ANSWER [PROMPT ANSWER ...] -- COMMAND...
Prints everything the command wrote; exits with its status, or 124 after 60 s.
Answers go in only once their prompt is on screen: gpg flushes typed-ahead
input before it asks for a passphrase.
"""

import os
import pty
import select
import sys
import time

split = sys.argv.index("--")
pairs = sys.argv[1:split]
answers = list(zip(pairs[0::2], pairs[1::2]))
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[split + 1], sys.argv[split + 1 :])
seen, deadline = b"", time.monotonic() + 60
while time.monotonic() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.2)
    if ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
        sys.stdout.write(chunk.decode(errors="replace"))
        sys.stdout.flush()
    if answers and answers[0][0].encode() in seen:
        seen = seen.split(answers[0][0].encode(), 1)[1]
        os.write(fd, answers.pop(0)[1].encode() + b"\n")
else:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    sys.exit(124)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
