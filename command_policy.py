"""服务器命令只读安全策略。

规则：
1. 永远禁止：毁灭性命令（格式化磁盘、关机重启、fork 炸弹等），即使授权也不放行。
2. 变更类命令：默认拒绝，仅在 allow_advanced=True（用户主动授权）时放行。
3. 只读白名单：常用查询/诊断命令默认放行，支持管道组合（每段都需在白名单内）。
"""

import re
import shlex
from typing import Callable, Dict, List, Optional, Tuple

# 永远禁止的命令（即使授权也不放行）
ALWAYS_FORBIDDEN = [
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\b[^|]*\bof=/dev/",
    r"\b(shutdown|reboot|halt|poweroff|init\s+[06])\b",
    r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(/{1,2}(\s|$)|/~|/\*|\$HOME|\.)",
    r":\(\)\s*\{",
    r"\bchmod\s+-R\s+777\s+/(?:\s|$)",
    r">\s*/dev/sd[a-z]",
    r"\bchown\s+-R\s+\S+\s+/(?:\s|$)",
]

# 变更类结构特征（对整条命令生效）：命中则要求授权。
# 命令级变更（rm/kill/docker run 等）由段首词不在只读白名单覆盖。
MUTATION_PATTERNS = [
    r"\d?>\s*[^\s&|]",                        # 输出重定向 > file（2>&1 不受影响）
    r"(^|\s)&(\s|$)",                          # 后台执行 &
    r"\bsed\s+(-i|--in-place)\b",              # sed 原地编辑
    r"\bsystemctl\s+(start|stop|restart|reload|try-restart|enable|disable|mask|unmask|kill|isolate|set-default|daemon-reload|reset-failed)\b",
    r"\bservice\s+\S+\s+(start|stop|restart|reload|force-reload)\b",
    r"\bhostnamectl\s+set",
    r"\bxargs\b",
]

# 只读白名单：命令 -> 参数校验函数（None 表示任意参数均可）
READONLY_COMMANDS: Dict[str, Callable[[List[str]], bool]] = {
    # 文件查看
    "cat": None, "head": None, "tail": None, "grep": None, "zgrep": None, "egrep": None,
    "fgrep": None, "rg": None, "awk": None, "cut": None, "tr": None, "sort": None,
    "uniq": None, "wc": None, "column": None, "diff": None, "comm": None, "join": None,
    "paste": None, "ls": None, "ll": None, "pwd": None, "stat": None, "file": None,
    "readlink": None, "realpath": None, "basename": None, "dirname": None, "tree": None,
    "sha256sum": None, "md5sum": None, "cksum": None,
    # 系统信息
    "echo": None, "printf": None, "date": None, "cal": None, "seq": None,
    "hostname": None, "uname": None, "whoami": None, "id": None, "groups": None,
    "uptime": None, "w": None, "who": None, "last": None, "lastlog": None, "users": None,
    "ps": None, "top": None, "pidof": None, "pgrep": None, "pstree": None, "nproc": None,
    "free": None, "vmstat": None, "iostat": None, "mpstat": None, "pidstat": None,
    "sar": None, "lscpu": None, "lsblk": None, "lspci": None, "lsusb": None, "lshw": None,
    "df": None, "du": None, "env": None, "printenv": None, "locale": None,
    "nvidia-smi": None, "ethtool": None, "getenforce": None, "sestatus": None, "dmesg": None,
    "journalctl": None, "sleep": None, "bc": None, "expr": None, "true": None,
    # 网络（查询）
    "netstat": None, "ss": None, "lsof": None, "arp": None, "route": None, "ifconfig": None,
    "ping": None, "traceroute": None, "tracepath": None, "dig": None, "nslookup": None,
    "host": None, "which": None, "whereis": None, "type": None,
}


def _find_check(args: List[str]) -> bool:
    """find 仅允许查询参数，禁止删除/执行类动作。"""
    banned = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprintf", "-fls"}
    return not any(arg in banned or arg.startswith("-fprint") for arg in args)


def _ip_check(args: List[str]) -> bool:
    """ip 仅允许查询子命令。"""
    readonly_sub = {"addr", "a", "route", "r", "link", "l", "neigh", "n", "rule", "tunnel",
                    "addrlabel", "maddr", "mroute", "show", "list"}
    mutating = {"set", "add", "del", "delete", "flush", "change", "replace", "monitor"}
    if not args:
        return True
    return args[0] in readonly_sub and not any(tok in mutating for tok in args)


def _ifconfig_check(args: List[str]) -> bool:
    """ifconfig 无参数或仅带设备名/查看选项时为只读。"""
    mutating = {"up", "down", "arp", "promisc", "allmulti", "multicast", "mtu", "netmask", "add", "del", "hw"}
    return not args or not any(arg in mutating or re.match(r"^\d+\.\d+\.\d+\.\d+$", arg) for arg in args)


def _route_check(args: List[str]) -> bool:
    """route 仅允许查看。"""
    readonly_flags = {"-n", "-e", "-F", "-C", "-v", "--help"}
    return not args or all(arg in readonly_flags for arg in args)


def _systemctl_check(args: List[str]) -> bool:
    """systemctl 仅允许状态查询子命令。"""
    readonly_sub = {"status", "show", "list-units", "list-unit-files", "is-active", "is-enabled",
                    "is-failed", "cat", "help", "list-dependencies", "list-timers", "list-sockets",
                    "list-targets", "list-jobs", "get-default", "show-environment"}
    return bool(args) and args[0] in readonly_sub


def _service_check(args: List[str]) -> bool:
    """service 仅允许 status。"""
    return len(args) >= 2 and args[1] == "status"


def _docker_check(args: List[str]) -> bool:
    """docker/podman 仅允许查询子命令。"""
    readonly_sub = {"ps", "images", "image", "inspect", "stats", "version", "info", "top",
                    "history", "logs", "port", "diff", "search"}
    return bool(args) and args[0] in readonly_sub


def _kubectl_check(args: List[str]) -> bool:
    """kubectl 仅允许查询子命令。"""
    readonly_sub = {"get", "describe", "logs", "top", "version", "explain", "cluster-info",
                    "auth", "api-resources"}
    return bool(args) and args[0] in readonly_sub


def _crontab_check(args: List[str]) -> bool:
    """crontab 仅允许 -l 查看列表。"""
    return "-l" in args


def _iptables_check(args: List[str]) -> bool:
    """iptables 仅允许 -L / -S 查看。"""
    return any(arg in {"-L", "-S", "--list", "--list-rules"} for arg in args)


def _supervisorctl_check(args: List[str]) -> bool:
    """supervisorctl 仅允许状态查询。"""
    return not args or args[0] in {"status", "avail", "version", "pid", "tail", "read"}


def _pm2_check(args: List[str]) -> bool:
    """pm2 仅允许查询子命令。"""
    return bool(args) and args[0] in {"list", "ls", "status", "logs", "describe", "show",
                                      "prettylist", "jlist", "info"}


def _curl_check(args: List[str]) -> bool:
    """curl 仅允许 GET 类查询。"""
    banned = {"-d", "--data", "--data-raw", "--data-urlencode", "-X", "--request", "-T",
              "--upload-file", "-F", "--form", "-o", "--output", "-O", "-K", "--config",
              "--cookie", "-b", "-C", "--continue-at"}
    return not any(arg in banned for arg in args)


def _mount_check(args: List[str]) -> bool:
    """mount 无参数时为查看挂载点。"""
    return not args


def _hostnamectl_check(args: List[str]) -> bool:
    return not args or args[0] == "status"


def _sed_check(args: List[str]) -> bool:
    """sed 禁止 -i 原地编辑。"""
    return not any(arg == "-i" or arg.startswith("-i") or arg == "--in-place" for arg in args)


def _awk_check(args: List[str]) -> bool:
    """awk 禁止 system()/getline 等可执行外部命令的用法。"""
    joined = " ".join(args).lower()
    return not any(token in joined for token in ("system(", "getline", "|&", "close("))


def _any_args(args: List[str]) -> bool:
    """无特殊校验的命令默认放行。"""
    return True


# None 项统一替换为默认放行
READONLY_COMMANDS = {k: (v if v is not None else _any_args) for k, v in READONLY_COMMANDS.items()}


# 带参数校验的命令注册
CHECKED_COMMANDS: Dict[str, Callable[[List[str]], bool]] = {
    "find": _find_check,
    "ip": _ip_check,
    "ifconfig": _ifconfig_check,
    "route": _route_check,
    "systemctl": _systemctl_check,
    "service": _service_check,
    "docker": _docker_check,
    "podman": _docker_check,
    "crictl": _docker_check,
    "kubectl": _kubectl_check,
    "crontab": _crontab_check,
    "iptables": _iptables_check,
    "supervisorctl": _supervisorctl_check,
    "pm2": _pm2_check,
    "curl": _curl_check,
    "mount": _mount_check,
    "hostnamectl": _hostnamectl_check,
    "sed": _sed_check,
    "awk": _awk_check,
}

READONLY_COMMANDS.update(CHECKED_COMMANDS)


def _split_segments(command: str) -> List[str]:
    """按管道与逻辑分隔符切分为多段，逐段校验。"""
    return [seg for seg in re.split(r"\|\||&&|\||;", command) if seg.strip()]


def _first_word_and_args(segment: str) -> Tuple[Optional[str], List[str]]:
    """取出命令首词与参数，跳过 sudo 与 KEY=VALUE 环境变量前缀。"""
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    idx = 0
    while idx < len(tokens) and (tokens[idx] == "sudo" or re.match(r"^[A-Za-z_]\w*=", tokens[idx])):
        idx += 1
    if idx >= len(tokens):
        return None, []
    return tokens[idx], tokens[idx + 1:]


def validate_command(command: str, allow_advanced: bool = False) -> Tuple[bool, str]:
    """校验命令是否允许执行。

    :param command: 待执行命令（单行）
    :param allow_advanced: 是否已获得用户授权执行变更类命令
    :return: (是否放行, 拒绝原因)
    """
    statement = (command or "").strip()
    if not statement:
        return False, "命令不能为空"
    if "\n" in statement:
        return False, "仅支持单行命令"

    for pattern in ALWAYS_FORBIDDEN:
        if re.search(pattern, statement):
            return False, "命令包含被永久禁止的危险操作，无法执行"

    if re.search(r"\$\(|`|\>\(", statement):
        return False, "只读模式禁止命令替换（$() / 反引号 / 进程替换）"

    if allow_advanced:
        return True, ""

    for pattern in MUTATION_PATTERNS:
        if re.search(pattern, statement):
            return False, "命令包含变更类操作，需获得用户授权后设置 allow_advanced=True"

    for segment in _split_segments(statement):
        word, args = _first_word_and_args(segment)
        if word is None:
            continue
        checker = READONLY_COMMANDS.get(word)
        if checker is None:
            return False, "命令 '%s' 不在只读白名单内；如确需执行请先获得用户授权并设置 allow_advanced=True" % word
        if args and not checker(args):
            return False, "命令 '%s' 的当前用法不在只读范围内；如确需执行请获得用户授权后设置 allow_advanced=True" % word
    return True, ""
