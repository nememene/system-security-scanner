#!/usr/bin/env python3
"""电脑安全监控扫描工具 - 扫描任务管理器进程并生成分析报告。"""

import argparse
import os
import sys

# 确保从脚本所在目录加载本地模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report_formatter import format_report, save_report
from scanner import run_scan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="扫描电脑运行进程，分析是否存在监控软件、入侵或病毒风险"
    )
    parser.add_argument(
        "-o", "--output",
        help="将报告保存到指定目录（默认保存到当前目录）",
        metavar="DIR",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="不保存报告文件，仅在屏幕打印",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=30,
        help="进程列表显示前 N 个（按内存排序，默认 30）",
    )
    args = parser.parse_args()

    # Windows 控制台 UTF-8 输出
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except AttributeError:
            pass

    print("正在扫描系统进程与网络连接，请稍候...")
    try:
        result = run_scan()
    except Exception as exc:
        print(f"扫描失败: {exc}", file=sys.stderr)
        return 1

    report_text = format_report(result, show_process_list=True, top_n=args.top)
    print(report_text)

    if not args.no_save:
        filepath = save_report(result, output_dir=args.output)
        print(f"报告已保存: {filepath}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
