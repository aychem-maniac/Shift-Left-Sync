# sls_scanner/cli/runner.py

import argparse
import time
from sls_scanner.core.pipeline import run_pipeline


def _fmt(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}분 {s:02d}초" if m else f"{s}초"


def run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="Shift-Left-Sync 보안 점검 도구"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="대상을 스캔한다.")

    scan_parser.add_argument(
        "--target",
        required=True,
        nargs="+",
        action="append",
        help="스캔 대상 URL 또는 IP (여러 개 가능)"
    )

    scan_parser.add_argument(
        "--strength",
        choices=["low", "medium", "high"],
        default="medium",
        help="스캔 강도 (default: medium)"
    )

    args = parser.parse_args()

    if args.command == "scan":
        targets     = [t for group in args.target for t in group]
        total_start = time.time()

        print(f"[INFO] Total targets: {len(targets)} / Strength: {args.strength}")

        per_times = []

        for idx, target in enumerate(targets, start=1):
            print(f"\n{'='*55}")
            print(f"[INFO] [{idx}/{len(targets)}] Scanning: {target}")
            print(f"{'='*55}")

            t0 = time.time()
            run_pipeline(target=target, strength=args.strength)
            elapsed = time.time() - t0
            per_times.append((target, elapsed))

            print(f"[TIME] {target} 소요 시간: {_fmt(elapsed)}")

        total_elapsed = time.time() - total_start

        if len(targets) > 1:
            print(f"\n{'='*55}")
            print(f"[TIME] 타겟별 소요 시간")
            for target, t in per_times:
                print(f"       {target}  →  {_fmt(t)}")
            print(f"[TIME] 전체 총 소요 시간: {_fmt(total_elapsed)}")
            print(f"{'='*55}")

    else:
        parser.print_help()