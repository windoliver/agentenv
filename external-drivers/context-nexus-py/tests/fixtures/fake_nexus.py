import signal
import sys
import time


running = True


def stop(_signum, _frame):
    global running
    running = False


def main():
    if sys.argv[1:2] == ["--version"]:
        print("nexus 0.0.0-test")
        return 0
    if sys.argv[1:4] != ["mcp", "serve", "--transport"]:
        print(f"unexpected fake nexus args: {sys.argv[1:]}", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
