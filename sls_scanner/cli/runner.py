# sls_scanner/cli/runner.py

import argparse
from sls_scanner.core.pipeline import run_pipeline


def run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="Shift-Left-Sync 보안 점검 도구"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="대상을 스캔한다.")

    # 다중 타겟 지원
    scan_parser.add_argument(
        "--target",
        required=True,
        nargs="+",
        action="append",
        help="스캔 대상 URL 또는 IP (여러 개 가능)"
    )

    # 스캔 강도
    scan_parser.add_argument(
        "--strength",
        choices=["low", "medium", "high"],
        default="medium",
        help="스캔 강도 (default: medium)"
    )

    args = parser.parse_args()

    if args.command == "scan":
        targets = [t for group in args.target for t in group]
        print(f"[INFO] Total targets: {len(targets)} / Strength: {args.strength}")

        for idx, target in enumerate(targets, start=1):
            print(f"\n{'='*55}")
            print(f"[INFO] [{idx}/{len(targets)}] Scanning: {target}")
            print(f"{'='*55}")
            run_pipeline(target=target, strength=args.strength)
    else:
        parser.print_help()
