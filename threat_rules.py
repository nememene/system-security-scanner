"""威胁特征规则库：监控软件、远程控制、常见恶意软件模式。"""

from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


@dataclass(frozen=True)
class ThreatRule:
    pattern: str
    category: str
    level: RiskLevel
    description: str


# 远程控制 / 屏幕监控 / 员工监控类软件（名称匹配，不区分大小写）
MONITORING_RULES: list[ThreatRule] = [
    ThreatRule("teamviewer", "远程监控", RiskLevel.MEDIUM, "TeamViewer 远程桌面控制"),
    ThreatRule("anydesk", "远程监控", RiskLevel.MEDIUM, "AnyDesk 远程桌面控制"),
    ThreatRule("todesk", "远程监控", RiskLevel.MEDIUM, "ToDesk 远程桌面控制"),
    ThreatRule("sunlogin", "远程监控", RiskLevel.MEDIUM, "向日葵远程控制"),
    ThreatRule("oray", "远程监控", RiskLevel.MEDIUM, "花生壳/向日葵相关组件"),
    ThreatRule("rustdesk", "远程监控", RiskLevel.MEDIUM, "RustDesk 远程桌面"),
    ThreatRule("vnc", "远程监控", RiskLevel.MEDIUM, "VNC 远程桌面"),
    ThreatRule("ultravnc", "远程监控", RiskLevel.MEDIUM, "UltraVNC 远程控制"),
    ThreatRule("realvnc", "远程监控", RiskLevel.MEDIUM, "RealVNC 远程控制"),
    ThreatRule("tightvnc", "远程监控", RiskLevel.MEDIUM, "TightVNC 远程控制"),
    ThreatRule("radmin", "远程监控", RiskLevel.MEDIUM, "Radmin 远程控制"),
    ThreatRule("splashtop", "远程监控", RiskLevel.MEDIUM, "Splashtop 远程访问"),
    ThreatRule("logmein", "远程监控", RiskLevel.MEDIUM, "LogMeIn 远程访问"),
    ThreatRule("parsec", "远程监控", RiskLevel.LOW, "Parsec 远程串流（游戏/远程）"),
    ThreatRule("screenconnect", "远程监控", RiskLevel.MEDIUM, "ConnectWise ScreenConnect"),
    ThreatRule("bomgar", "远程监控", RiskLevel.MEDIUM, "BeyondTrust 远程支持"),
    ThreatRule("activtrak", "员工监控", RiskLevel.HIGH, "ActivTrak 员工行为监控"),
    ThreatRule("teramind", "员工监控", RiskLevel.HIGH, "Teramind 员工监控"),
    ThreatRule("hubstaff", "员工监控", RiskLevel.HIGH, "Hubstaff 工时/活动监控"),
    ThreatRule("timedoctor", "员工监控", RiskLevel.HIGH, "Time Doctor 员工监控"),
    ThreatRule("workpuls", "员工监控", RiskLevel.HIGH, "Workpuls 员工监控"),
    ThreatRule("veriato", "员工监控", RiskLevel.HIGH, "Veriato 员工监控"),
    ThreatRule("refog", "键盘记录", RiskLevel.HIGH, "Refog 键盘记录器"),
    ThreatRule("ardamax", "键盘记录", RiskLevel.HIGH, "Ardamax 键盘记录器"),
    ThreatRule("keylogger", "键盘记录", RiskLevel.HIGH, "键盘记录器"),
    ThreatRule("spyrix", "监控软件", RiskLevel.HIGH, "Spyrix 监控软件"),
    ThreatRule("mspy", "监控软件", RiskLevel.HIGH, "mSpy 手机/电脑监控"),
    ThreatRule("flexispy", "监控软件", RiskLevel.HIGH, "FlexiSPY 监控软件"),
    ThreatRule("obs64", "录屏软件", RiskLevel.LOW, "OBS 录屏（需确认是否本人使用）"),
    ThreatRule("obs32", "录屏软件", RiskLevel.LOW, "OBS 录屏（需确认是否本人使用）"),
    ThreatRule("bandicam", "录屏软件", RiskLevel.LOW, "Bandicam 录屏"),
    ThreatRule("camtasia", "录屏软件", RiskLevel.LOW, "Camtasia 录屏"),
]

# 入侵 / 恶意软件常见进程名
MALWARE_RULES: list[ThreatRule] = [
    ThreatRule("coinminer", "挖矿木马", RiskLevel.HIGH, "加密货币挖矿程序"),
    ThreatRule("xmrig", "挖矿木马", RiskLevel.HIGH, "XMRig 挖矿程序"),
    ThreatRule("minergate", "挖矿木马", RiskLevel.HIGH, "MinerGate 挖矿"),
    ThreatRule("njrat", "远控木马", RiskLevel.HIGH, "njRAT 远控木马"),
    ThreatRule("darkcomet", "远控木马", RiskLevel.HIGH, "DarkComet 远控"),
    ThreatRule("quasar", "远控木马", RiskLevel.MEDIUM, "Quasar RAT（需结合路径判断）"),
    ThreatRule("asyncrat", "远控木马", RiskLevel.HIGH, "AsyncRAT 远控"),
    ThreatRule("remcos", "远控木马", RiskLevel.HIGH, "Remcos 远控"),
    ThreatRule("nanocore", "远控木马", RiskLevel.HIGH, "NanoCore 远控"),
    ThreatRule("emotet", "木马病毒", RiskLevel.HIGH, "Emotet 银行木马"),
    ThreatRule("trickbot", "木马病毒", RiskLevel.HIGH, "TrickBot 木马"),
    ThreatRule("wannacry", "勒索病毒", RiskLevel.HIGH, "WannaCry 勒索病毒"),
    ThreatRule("locky", "勒索病毒", RiskLevel.HIGH, "Locky 勒索病毒"),
    ThreatRule("ryuk", "勒索病毒", RiskLevel.HIGH, "Ryuk 勒索病毒"),
    ThreatRule("mimikatz", "黑客工具", RiskLevel.HIGH, "Mimikatz 凭证窃取工具"),
    ThreatRule("psexec", "黑客工具", RiskLevel.MEDIUM, "PsExec 横向移动工具"),
    ThreatRule("metasploit", "黑客工具", RiskLevel.HIGH, "Metasploit 渗透框架"),
    ThreatRule("cobalt", "黑客工具", RiskLevel.MEDIUM, "Cobalt Strike 相关（需结合路径）"),
]

# 系统进程伪装：合法名称应位于这些目录
SYSTEM_PROCESS_PATHS: dict[str, list[str]] = {
    "svchost.exe": [r"\windows\system32", r"\windows\syswow64"],
    "csrss.exe": [r"\windows\system32"],
    "lsass.exe": [r"\windows\system32"],
    "services.exe": [r"\windows\system32"],
    "smss.exe": [r"\windows\system32"],
    "wininit.exe": [r"\windows\system32"],
    "winlogon.exe": [r"\windows\system32"],
    "explorer.exe": [r"\windows"],
    "dllhost.exe": [r"\windows\system32", r"\windows\syswow64"],
    "conhost.exe": [r"\windows\system32"],
}

# 白名单路径：这些厂商目录下的 Roaming 程序视为正常
SAFE_ROAMING_VENDORS = (
    r"\tencent",
    r"\microsoft",
    r"\google",
    r"\mozilla",
    r"\adobe",
    r"\dingtalk",
    r"\bytedance",
)

# 高风险启动路径关键词
SUSPICIOUS_PATH_KEYWORDS: list[tuple[str, RiskLevel, str]] = [
    (r"\appdata\local\temp", RiskLevel.HIGH, "从临时目录运行"),
    (r"\windows\temp", RiskLevel.HIGH, "从 Windows 临时目录运行"),
    (r"\users\public", RiskLevel.MEDIUM, "从 Public 目录运行"),
    (r"\appdata\roaming", RiskLevel.MEDIUM, "从 Roaming 目录运行（部分正常软件也会在此）"),
    (r"\downloads", RiskLevel.MEDIUM, "从下载目录直接运行"),
    (r"\programdata", RiskLevel.LOW, "从 ProgramData 运行"),
]

# 可疑父子进程关系：(子进程关键词, 父进程关键词, 描述)
SUSPICIOUS_PARENT_CHILD: list[tuple[str, str, str]] = [
    ("cmd.exe", "winword.exe", "Word 文档宏可能启动命令行"),
    ("cmd.exe", "excel.exe", "Excel 宏可能启动命令行"),
    ("powershell.exe", "winword.exe", "Word 宏可能启动 PowerShell"),
    ("powershell.exe", "outlook.exe", "Outlook 附件可能启动 PowerShell"),
    ("wscript.exe", "explorer.exe", "脚本宿主异常启动"),
    ("cscript.exe", "explorer.exe", "脚本宿主异常启动"),
    ("mshta.exe", "explorer.exe", "HTA 脚本可能用于攻击"),
]

# 高风险监听端口
SUSPICIOUS_LISTEN_PORTS: dict[int, str] = {
    4444: "Metasploit 默认端口",
    5555: "ADB/部分远控默认端口",
    6666: "常见后门端口",
    7777: "常见后门端口",
    8888: "常见代理/后门端口",
    9999: "常见后门端口",
    31337: "经典后门端口 (elite)",
    12345: "NetBus 木马历史端口",
    27374: "SubSeven 木马历史端口",
}
