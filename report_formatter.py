"""扫描报告格式化输出。"""

from __future__ import annotations

import os
from collections import Counter

from scanner import ScanResult
from threat_rules import RiskLevel


LEVEL_ICON = {
    RiskLevel.HIGH: "[!!!]",
    RiskLevel.MEDIUM: "[!! ]",
    RiskLevel.LOW: "[!  ]",
    RiskLevel.INFO: "[ i ]",
}


def _separator(char: str = "=", width: int = 72) -> str:
    return char * width


def _overall_verdict(result: ScanResult) -> tuple[str, str]:
    counts = Counter(f.level for f in result.findings)
    high = counts[RiskLevel.HIGH]
    medium = counts[RiskLevel.MEDIUM]

    if high >= 3:
        return "严重警告", "发现多项高危迹象，电脑可能存在被监控、入侵或病毒感染，建议立即断网并全盘杀毒。"
    if high >= 1:
        return "存在风险", "发现高危项，请优先核查下列告警并确认是否为本人安装的软件。"
    if medium >= 3:
        return "需要关注", "存在若干中危项，可能包含远程控制或可疑行为，建议人工确认。"
    if medium >= 1 or counts[RiskLevel.LOW] >= 5:
        return "基本正常", "未发现明显高危威胁，但存在少量需关注的项目，建议定期复查。"
    return "状态良好", "未发现明显监控、入侵或病毒特征，但仍建议保持杀毒软件更新。"


def format_report(result: ScanResult, show_process_list: bool = True, top_n: int = 30) -> str:
    verdict_title, verdict_detail = _overall_verdict(result)
    lines: list[str] = []

    lines.append(_separator())
    lines.append("              电脑安全监控分析报告")
    lines.append(_separator())
    lines.append(f"扫描时间   : {result.scan_time}")
    lines.append(f"计算机名   : {result.hostname}")
    lines.append(f"操作系统   : {result.os_info}")
    lines.append(f"进程总数   : {result.process_count}")
    lines.append(_separator("-"))
    lines.append(f"综合评估   : {verdict_title}")
    lines.append(f"评估说明   : {verdict_detail}")
    lines.append(_separator("-"))

    counts = Counter(f.level for f in result.findings)
    lines.append("风险统计:")
    lines.append(f"  高危: {counts[RiskLevel.HIGH]}  |  中危: {counts[RiskLevel.MEDIUM]}  |  低危: {counts[RiskLevel.LOW]}  |  信息: {counts[RiskLevel.INFO]}")
    lines.append(_separator("-"))

    if result.findings:
        lines.append("详细告警:")
        lines.append("")
        for idx, finding in enumerate(result.findings, 1):
            icon = LEVEL_ICON[finding.level]
            lines.append(f"{idx:>3}. {icon} [{finding.level.value}] {finding.category} - {finding.title}")
            lines.append(f"       {finding.detail}")
            if finding.pid is not None:
                lines.append(f"       PID: {finding.pid}")
            lines.append("")
    else:
        lines.append("详细告警: 无")
        lines.append("")

    if show_process_list:
        lines.append(_separator("-"))
        lines.append(f"任务管理器进程列表 (按内存占用 Top {top_n}):")
        lines.append("")
        lines.append(f"{'PID':>8}  {'内存MB':>8}  {'CPU%':>6}  {'进程名':<24}  用户")
        lines.append("-" * 72)
        for proc in result.processes[:top_n]:
            name = proc.name[:24]
            user = (proc.username or "")[:20]
            lines.append(
                f"{proc.pid:>8}  {proc.memory_mb:>8.1f}  {proc.cpu_percent:>6.1f}  {name:<24}  {user}"
            )
        lines.append("")

    lines.append(_separator("-"))
    lines.append("检测维度说明:")
    lines.append("  1. 监控软件  - 远程桌面、员工监控、键盘记录、录屏等")
    lines.append("  2. 入侵迹象  - 伪装系统进程、异常父子进程、可疑端口监听")
    lines.append("  3. 病毒感染  - 挖矿木马、远控木马、勒索病毒特征匹配")
    lines.append("  4. 可疑行为  - 临时目录运行、无路径进程、高资源占用")
    lines.append("")
    lines.append("免责声明:")
    lines.append("  本工具基于进程名/路径/网络等启发式规则扫描，不能替代专业杀毒软件。")
    lines.append("  误报和漏报均可能存在，高危项请结合实际情况人工判断。")
    lines.append(_separator())

    return "\n".join(lines)


def save_report(result: ScanResult, output_dir: str | None = None) -> str:
    if output_dir is None:
        output_dir = os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    filename = f"security_report_{result.scan_time.replace(':', '').replace(' ', '_')}.txt"
    filepath = os.path.join(output_dir, filename)
    content = format_report(result, show_process_list=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath
