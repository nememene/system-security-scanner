"""系统进程与安全状态扫描引擎。"""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime

import psutil

from threat_rules import (
    MALWARE_RULES,
    MONITORING_RULES,
    SAFE_ROAMING_VENDORS,
    SUSPICIOUS_LISTEN_PORTS,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_PATH_KEYWORDS,
    SYSTEM_PROCESS_PATHS,
    RiskLevel,
    ThreatRule,
)


@dataclass
class Finding:
    level: RiskLevel
    category: str
    title: str
    detail: str
    pid: int | None = None
    process_name: str | None = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str
    username: str
    cpu_percent: float
    memory_mb: float
    status: str
    create_time: str
    parent_name: str
    parent_pid: int | None
    cmdline: str


@dataclass
class ScanResult:
    scan_time: str
    hostname: str
    os_info: str
    process_count: int
    processes: list[ProcessInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _safe_text(value) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return "<无法读取>"


def _match_rules(name: str, exe: str, rules: list[ThreatRule]) -> list[ThreatRule]:
    """按进程名与路径匹配规则，短关键词避免子串误报（如 TSVNCache 不含 vnc 独立词）。"""
    name_lower = name.lower()
    exe_lower = exe.lower()
    matched: list[ThreatRule] = []
    seen_patterns: set[str] = set()

    for rule in rules:
        pattern = rule.pattern
        if pattern in seen_patterns:
            continue

        hit = False
        # 进程名：整词匹配或名称以模式开头（如 sunloginclient）
        if pattern in name_lower:
            if len(pattern) >= 5 or name_lower.startswith(pattern) or f"{pattern}." in name_lower:
                hit = True
        # 路径：较长模式或路径分段匹配
        if not hit and pattern in exe_lower:
            if len(pattern) >= 5 or f"\\{pattern}" in exe_lower or f"/{pattern}" in exe_lower:
                hit = True

        if hit:
            matched.append(rule)
            seen_patterns.add(pattern)

    return matched


def _get_process_list() -> list[ProcessInfo]:
    processes: list[ProcessInfo] = []
    name_cache: dict[int, str] = {}

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name_cache[proc.info["pid"]] = _safe_text(proc.info.get("name"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "username", "cpu_percent", "memory_info", "status", "create_time", "ppid", "cmdline"]
    ):
        try:
            info = proc.info
            pid = info["pid"]
            ppid = info.get("ppid")
            mem = info.get("memory_info")
            memory_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0.0
            create_time = datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S") if info.get("create_time") else ""
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list) if cmdline_list else ""

            processes.append(
                ProcessInfo(
                    pid=pid,
                    name=_safe_text(info.get("name")),
                    exe=_safe_text(info.get("exe")),
                    username=_safe_text(info.get("username")),
                    cpu_percent=round(info.get("cpu_percent") or 0.0, 1),
                    memory_mb=memory_mb,
                    status=_safe_text(info.get("status")),
                    create_time=create_time,
                    parent_name=name_cache.get(ppid, ""),
                    parent_pid=ppid,
                    cmdline=cmdline,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda p: p.memory_mb, reverse=True)
    return processes


def _check_process_impersonation(proc: ProcessInfo, findings: list[Finding]) -> None:
    name_lower = proc.name.lower()
    exe_lower = proc.exe.lower()
    expected_dirs = SYSTEM_PROCESS_PATHS.get(name_lower)
    if not expected_dirs:
        return
    if not exe_lower:
        findings.append(
            Finding(
                level=RiskLevel.HIGH,
                category="进程伪装",
                title=f"系统进程无路径: {proc.name}",
                detail="关键系统进程无法读取可执行文件路径，可能被隐藏或注入",
                pid=proc.pid,
                process_name=proc.name,
            )
        )
        return
    if not any(expected in exe_lower for expected in expected_dirs):
        findings.append(
            Finding(
                level=RiskLevel.HIGH,
                category="进程伪装",
                title=f"疑似伪装系统进程: {proc.name}",
                detail=f"路径异常: {proc.exe}（正常应在 System32 等系统目录）",
                pid=proc.pid,
                process_name=proc.name,
            )
        )


def _check_suspicious_paths(proc: ProcessInfo, findings: list[Finding]) -> None:
    if not proc.exe:
        return
    exe_lower = proc.exe.lower()
    for keyword, level, reason in SUSPICIOUS_PATH_KEYWORDS:
        if keyword not in exe_lower:
            continue
        if keyword == r"\appdata\roaming":
            if any(vendor in exe_lower for vendor in SAFE_ROAMING_VENDORS):
                continue
        findings.append(
            Finding(
                level=level,
                category="可疑路径",
                title=f"可疑运行位置: {proc.name}",
                detail=f"{reason} | {proc.exe}",
                pid=proc.pid,
                process_name=proc.name,
            )
        )
        break


def _check_parent_child(proc: ProcessInfo, findings: list[Finding]) -> None:
    child = proc.name.lower()
    parent = proc.parent_name.lower()
    for child_key, parent_key, desc in SUSPICIOUS_PARENT_CHILD:
        if child_key in child and parent_key in parent:
            findings.append(
                Finding(
                    level=RiskLevel.HIGH,
                    category="可疑行为",
                    title=f"异常父子进程: {proc.parent_name} -> {proc.name}",
                    detail=desc,
                    pid=proc.pid,
                    process_name=proc.name,
                )
            )


def _check_no_path_process(proc: ProcessInfo, findings: list[Finding]) -> None:
    if proc.exe:
        return
    # 排除系统空闲进程等
    if proc.pid in (0, 4):
        return
    findings.append(
        Finding(
            level=RiskLevel.MEDIUM,
            category="隐藏进程",
            title=f"进程无执行路径: {proc.name}",
            detail="无法获取可执行文件路径，可能是权限限制或进程隐藏技术",
            pid=proc.pid,
            process_name=proc.name,
        )
    )


def _check_high_resource(proc: ProcessInfo, findings: list[Finding]) -> None:
    if proc.cpu_percent >= 80:
        findings.append(
            Finding(
                level=RiskLevel.MEDIUM,
                category="资源异常",
                title=f"CPU 占用极高: {proc.name}",
                detail=f"CPU {proc.cpu_percent}% | PID {proc.pid}",
                pid=proc.pid,
                process_name=proc.name,
            )
        )
    if proc.memory_mb >= 2048:
        findings.append(
            Finding(
                level=RiskLevel.LOW,
                category="资源异常",
                title=f"内存占用较高: {proc.name}",
                detail=f"内存 {proc.memory_mb} MB | PID {proc.pid}",
                pid=proc.pid,
                process_name=proc.name,
            )
        )


def _check_network(findings: list[Finding]) -> None:
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        findings.append(
            Finding(
                level=RiskLevel.INFO,
                category="网络扫描",
                title="网络连接扫描受限",
                detail="需要管理员权限才能完整扫描网络连接，请以管理员身份重新运行",
            )
        )
        return

    listening: dict[int, list[str]] = {}
    external_conns: list[str] = []

    for conn in connections:
        if not conn.laddr:
            continue
        lport = conn.laddr.port
        status = conn.status
        proc_name = ""
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = f"PID {conn.pid}"

        if status == psutil.CONN_LISTEN:
            listening.setdefault(lport, []).append(proc_name)
            if lport in SUSPICIOUS_LISTEN_PORTS:
                findings.append(
                    Finding(
                        level=RiskLevel.HIGH,
                        category="可疑端口",
                        title=f"监听高风险端口 {lport}",
                        detail=f"{SUSPICIOUS_LISTEN_PORTS[lport]} | 进程: {', '.join(listening[lport])}",
                    )
                )

        if status == psutil.CONN_ESTABLISHED and conn.raddr:
            rip = conn.raddr.ip
            rport = conn.raddr.port
            if rip not in ("127.0.0.1", "::1", "0.0.0.0"):
                external_conns.append(f"{proc_name} -> {rip}:{rport}")

    if len(external_conns) > 50:
        findings.append(
            Finding(
                level=RiskLevel.MEDIUM,
                category="网络活动",
                title="外连数量较多",
                detail=f"检测到 {len(external_conns)} 条外向连接，建议结合进程逐一核查",
            )
        )


def _check_duplicate_names(processes: list[ProcessInfo], findings: list[Finding]) -> None:
    counts: dict[str, int] = {}
    for proc in processes:
        key = proc.name.lower()
        counts[key] = counts.get(key, 0) + 1

    for name, count in counts.items():
        if name in SYSTEM_PROCESS_PATHS and count > 150:
            findings.append(
                Finding(
                    level=RiskLevel.MEDIUM,
                    category="进程异常",
                    title=f"{name} 实例数量偏多",
                    detail=f"共 {count} 个实例，请确认是否存在伪装进程",
                )
            )


def _apply_rule_matches(proc: ProcessInfo, findings: list[Finding]) -> None:
    for rule in _match_rules(proc.name, proc.exe, MONITORING_RULES):
        findings.append(
            Finding(
                level=rule.level,
                category=rule.category,
                title=f"检测到: {rule.description}",
                detail=f"进程: {proc.name} | 路径: {proc.exe or '未知'} | PID: {proc.pid}",
                pid=proc.pid,
                process_name=proc.name,
            )
        )
    for rule in _match_rules(proc.name, proc.exe, MALWARE_RULES):
        findings.append(
            Finding(
                level=rule.level,
                category=rule.category,
                title=f"疑似恶意: {rule.description}",
                detail=f"进程: {proc.name} | 路径: {proc.exe or '未知'} | PID: {proc.pid}",
                pid=proc.pid,
                process_name=proc.name,
            )
        )


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """合并重复告警（同 PID + 同类别的监控软件只保留一条）。"""
    unique: list[Finding] = []
    seen_keys: set[tuple] = set()
    monitor_categories = {"远程监控", "员工监控", "键盘记录", "监控软件", "录屏软件"}

    for finding in findings:
        if finding.pid is not None and finding.category in monitor_categories:
            key = (finding.pid, finding.category)
        else:
            key = (finding.category, finding.title, finding.detail)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(finding)

    return unique


def run_scan() -> ScanResult:
    processes = _get_process_list()
    findings: list[Finding] = []

    for proc in processes:
        _apply_rule_matches(proc, findings)
        _check_process_impersonation(proc, findings)
        _check_suspicious_paths(proc, findings)
        _check_parent_child(proc, findings)
        _check_no_path_process(proc, findings)
        _check_high_resource(proc, findings)

    _check_duplicate_names(processes, findings)
    _check_network(findings)

    findings = _deduplicate_findings(findings)

    # 按风险等级排序
    level_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2, RiskLevel.INFO: 3}
    findings.sort(key=lambda f: level_order[f.level])

    return ScanResult(
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        hostname=socket.gethostname(),
        os_info=f"{platform.system()} {platform.release()} ({platform.version()})",
        process_count=len(processes),
        processes=processes,
        findings=findings,
    )
