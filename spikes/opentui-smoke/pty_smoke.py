# PTY run of the real binary: send Down, Enter, q; require clean exit 0 and sane terminal restore sequences.
import os, pty, sys, time, select, struct, fcntl, termios
exe = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execv(exe, [exe])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
buf = b""
def pump(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: buf += os.read(fd, 65536)
            except OSError: return
pump(1.0)
os.write(fd, b"\x1b[B"); pump(0.3)
os.write(fd, b"\r"); pump(0.5)
os.write(fd, b"q"); pump(1.0)
_, status = os.waitpid(pid, 0)
ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
print("exit_status_ok:", ok, "bytes:", len(buf))
for needle in (b"Torwell", b"Show plan", b"\x1b[?1049h", b"\x1b[?1049l"):
    print(needle, needle in buf)
sel = b"Selected: Show plan" in buf
print("selected_status_in_raw_bytes (informational; diff-rendered output splits text):", sel)
sys.exit(0 if ok and b"Torwell" in buf and b"\x1b[?1049l" in buf else 1)
