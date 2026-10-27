"""overgrant scan [PATH] [--home] [--format text|json|sarif] [--fail-on LEVEL]."""

import argparse
import sys
from pathlib import Path

from . import __version__, report, rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="overgrant")
    parser.add_argument("--version", action="version", version=f"overgrant {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="scan local AI coding-agent configuration without executing it")
    scan.add_argument("path", nargs="?", type=Path, default=Path("."), help="repository directory")
    scan.add_argument("--home", action="store_true", help="also scan documented user config files")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--fail-on", choices=tuple(rules.SEVERITY), default="high")
    args = parser.parse_args(argv)
    try:
        result = rules.scan(args.path, args.home)
    except OSError:
        # OS exception text can contain untrusted names or details.
        print("overgrant: error: PATH must be an accessible repository directory", file=sys.stderr)
        return 2
    output = report.render(result, args.format) + "\n"
    if hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(output.encode("utf-8", errors="backslashreplace"))
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(output)
    return int(any(rules.SEVERITY[f["severity"]] >= rules.SEVERITY[args.fail_on]
                   for f in result["findings"]))


if __name__ == "__main__":
    sys.exit(main())
