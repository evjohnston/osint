#!/usr/bin/env python3
"""osintkit — all-in-one OSINT lookup.

    python3 osint.py torvalds
    python3 osint.py someone@example.com --pivot
    python3 osint.py example.com
    python3 osint.py 8.8.8.8
    python3 osint.py "+1 650 253 0000"

For the browser UI, run `python3 web.py` instead.
"""

import argparse
import sys
import time

from osintkit import report
from osintkit.core import investigate, load_env, save_report
from osintkit.detect import TYPES, detect


def main(argv=None):
    load_env()
    ap = argparse.ArgumentParser(description="All-in-one OSINT lookup (username, email, domain, IP, phone).")
    ap.add_argument("target", help="what to investigate")
    ap.add_argument("-t", "--type", choices=TYPES, help="force target type (auto-detected otherwise)")
    ap.add_argument("-p", "--pivot", action="store_true",
                    help="follow leads: email→domain+username, domain→IP")
    ap.add_argument("--quick", action="store_true",
                    help="skip the 600-site WhatsMyName username scan (~30 core sites only)")
    ap.add_argument("-o", "--out", default="reports", help="directory for JSON/HTML reports (default: reports/)")
    ap.add_argument("--no-save", action="store_true", help="don't write report files")
    ap.add_argument("--json", action="store_true", help="print JSON to stdout instead of the text summary")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    args = ap.parse_args(argv)
    quiet = args.quiet or args.json

    def on_section(title):
        if not quiet:
            sys.stderr.write(f"\r\033[K\n{report.c('1', title)}\n")

    def on_source(_title, name, res):
        if not quiet and res:
            sys.stderr.write(f"\r\033[K  {report.ICON[res['status']]} {name}")
            sys.stderr.flush()

    t0 = time.time()
    rep = investigate(args.target, args.type or detect(args.target), pivot=args.pivot, deep=not args.quick,
                      on_section=on_section, on_source=on_source)
    rep["elapsed_s"] = round(time.time() - t0, 1)
    if not quiet:
        sys.stderr.write("\r\033[K\n")

    if args.json:
        print(report.to_json(rep))
    else:
        report.print_report(rep)

    if not args.no_save:
        base = save_report(rep, args.out)
        if not args.json:
            print(f"\nSaved {base}.html and .json  ({rep['elapsed_s']}s)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
