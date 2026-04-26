# sls_scanner/cli/runner.py

import argparse

# 전체 스캔 흐름을 실행하는 함수를 가져온다.
from sls_scanner.core.pipeline import run_pipeline


def run_cli() -> None:
    # 명령어 인자를 처리하기 위한 parser를 만든다.
    parser = argparse.ArgumentParser(
        description="Shift-Left-Sync 기본 보안 점검 도구"
    )

    # 하위 명령어를 만들기 위한 subparsers를 생성한다.
    subparsers = parser.add_subparsers(dest="command")

    # scan 명령어를 추가한다.
    scan_parser = subparsers.add_parser(
        "scan",
        help="대상 URL 또는 IP를 스캔한다."
    )

    # scan 명령어에서 --target 옵션을 받는다.
    scan_parser.add_argument(
        "--target",
        required=True,
        help="스캔 대상 URL 또는 IP"
    )

    # 사용자가 입력한 명령어를 해석한다.
    args = parser.parse_args()

    # 사용자가 scan 명령어를 입력한 경우 파이프라인을 실행한다.
    if args.command == "scan":
        run_pipeline(args.target)
    else:
        # 명령어가 없거나 잘못된 경우 도움말을 출력한다.
        parser.print_help()