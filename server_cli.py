"""服务器只读诊断执行器。

支持两条通道：
1. JumpServer 主机资产（category=host，SSH 协议）：创建一次性连接 Token 后
   通过跳板机 SSH（KoKo）登录目标服务器交互式 Shell 执行命令。
2. 直连服务器（SERVER_DIRECT_SSH 配置）：在无法经跳板机授权时作为备用通道。

所有命令先经 command_policy.validate_command 校验：默认只读白名单，
变更类命令需 allow_advanced=True（用户主动授权），毁灭性命令永不放行。
"""

import json
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple

import paramiko

from command_policy import validate_command
from config import Settings
from db_cli import strip_ansi
from jumpserver_client import JumpServerClient

DONE_MARKER = "__MCP_DONE_"
_EXIT_PATTERN = re.compile(re.escape(DONE_MARKER) + r"(\d+)")
_BANNER = re.compile(
    r"^(Connecting to .*|Last login.*|Activate the web console.*|Welcome to .*|Type .* for help.*|"
    r"We trust you have.*|See `man sudo`.*|#\)|\s*$)"
)
_NAME_OK = re.compile(r"^[\w.@:+-]+$")


class ServerError(RuntimeError):
    """服务器命令执行失败。"""


def _quote(value: str) -> str:
    """对路径/关键字做 shell 单引号转义，防止注入。"""
    return shlex.quote(value)


class ServerCLI:
    """基于跳板机/直连的服务器只读诊断客户端。"""

    def __init__(self, settings: Settings, client: JumpServerClient) -> None:
        """:param settings: MCP 配置 :param client: JumpServer API 客户端"""
        self._settings = settings
        self._client = client
        self._ssh_host = settings.ssh_host or (
            settings.jumpserver_url.split("//", 1)[-1].split(":")[0] if settings.jumpserver_url else None
        )
        if not self._ssh_host:
            raise ServerError("无法确定跳板机 SSH 地址，请配置 JUMPSERVER_SSH_HOST")

    # ------------------------------------------------------------------ 资产

    def list_server_assets(self) -> Dict[str, Any]:
        """列出可查询的服务器（跳板机主机资产 + 配置的直连服务器）。"""
        hosts: List[Dict[str, Any]] = []
        hosts_error = ""
        try:
            assets = self._client._request(
                "GET", "/api/v1/perms/users/self/assets/?limit=1000"
            ).json().get("results", [])
            for asset in assets:
                if str((asset.get("category") or {}).get("value", "")) != "host":
                    continue
                hosts.append({
                    "id": asset.get("id"),
                    "name": asset.get("name"),
                    "address": asset.get("address"),
                    "protocols": [p.get("name") for p in asset.get("permed_protocols") or []],
                    "accounts": [a.get("alias") for a in asset.get("permed_accounts") or []],
                })
        except Exception as exc:
            hosts_error = str(exc)
        direct = [dict(name=d.get("name"), host=d.get("host"), port=d.get("port", 22),
                       username=d.get("username")) for d in self._settings.server_direct]
        return {
            "jumpserver_hosts": hosts,
            "jumpserver_hosts_error": hosts_error,
            "direct_servers": direct,
            "total": len(hosts) + len(direct),
        }

    def resolve_server(self, keyword: str = "") -> Tuple[str, Dict[str, Any]]:
        """按名称/地址定位服务器。

        :return: ("jump", {"asset":..., "account":...}) 或 ("direct", 配置字典)
        """
        hosts = [a for a in self.list_server_assets()["jumpserver_hosts"]
                 if "ssh" in [str(p) for p in a.get("protocols") or []]]
        if keyword:
            for conf in self._settings.server_direct:
                if keyword in (conf.get("name"), conf.get("host")):
                    return "direct", conf
            matched = [a for a in self.list_server_assets()["jumpserver_hosts"]
                       if keyword == a.get("id") or keyword == a.get("name")
                       or keyword.lower() in str(a.get("name", "")).lower()
                       or keyword.lower() in str(a.get("address", "")).lower()]
            if len(matched) == 1:
                return "jump", self._resolve_jump_account(matched[0], "")
            if len(matched) > 1:
                raise ServerError("服务器名称匹配到多个结果，请传入更精确的名称或资产 ID: %s"
                                  % [a["name"] for a in matched])
            raise ServerError("未找到服务器: %s；可先用 list_server_assets 查看可查服务器" % keyword)
        if hosts:
            return "jump", self._resolve_jump_account(hosts[0], "")
        if self._settings.server_direct:
            return "direct", self._settings.server_direct[0]
        raise ServerError("当前没有可查询的服务器：JumpServer 未授权 SSH 主机资产，也未配置 SERVER_DIRECT_SSH")

    def _resolve_jump_account(self, asset: Dict[str, Any], keyword: str) -> Dict[str, Any]:
        """解析主机资产的登录账号。"""
        detail = self._client.get_asset_detail(asset["id"])
        accounts = detail.get("permed_accounts") or []
        if not accounts:
            raise ServerError("资产 %s 没有授权账号" % asset.get("name"))
        if keyword:
            for account in accounts:
                if keyword in (account.get("alias"), account.get("name"), account.get("username")):
                    account["_asset"] = detail
                    return account
            raise ServerError("资产 %s 未授权账号: %s" % (asset.get("name"), keyword))
        account = accounts[0]
        account["_asset"] = detail
        return account

    # ------------------------------------------------------------------ 执行

    def run_command(
        self,
        command: str,
        server: str = "",
        timeout: Optional[int] = None,
        allow_advanced: bool = False,
        account: str = "",
    ) -> Dict[str, Any]:
        """在目标服务器上执行一条命令（先做只读策略校验）。

        :param command: 单行 shell 命令
        :param server: 服务器名称/地址关键字，为空时选择第一台可查服务器
        :param timeout: 命令超时秒数
        :param allow_advanced: 是否已获用户授权执行变更类命令（默认 False）
        :param account: 跳板机资产账号关键字
        :return: exit_code/output/timed_out/elapsed_ms 等
        """
        allowed, reason = validate_command(command, allow_advanced)
        if not allowed:
            raise ServerError(reason)
        kind, target = self.resolve_server(server)
        started = time.time()
        effective_timeout = timeout or self._settings.command_timeout
        if kind == "direct":
            result = self._run_direct(target, command, effective_timeout)
        else:
            result = self._run_jump(target, command, effective_timeout)
        result.update({
            "command": command,
            "server": target.get("name") or target.get("host"),
            "elapsed_ms": int((time.time() - started) * 1000),
        })
        return result

    def _run_direct(self, conf: Dict[str, Any], command: str, timeout: int) -> Dict[str, Any]:
        """直连通道：paramiko exec_command，stdout/stderr 分离。"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            conf["host"], port=int(conf.get("port", 22)), username=conf.get("username"),
            password=conf.get("password"), key_filename=conf.get("key_path"),
            timeout=15, allow_agent=False, look_for_keys=False,
        )
        try:
            channel = ssh.get_transport().open_session()
            channel.settimeout(1.0)
            channel.exec_command(command)
            out, err = b"", b""
            deadline = time.time() + timeout
            while True:
                if channel.recv_ready():
                    out += channel.recv(65536)
                if channel.recv_stderr_ready():
                    err += channel.recv_stderr(65536)
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.time() > deadline:
                    channel.close()
                    return {"exit_code": None, "output": out.decode("utf-8", "replace")[-50000:],
                            "error": err.decode("utf-8", "replace")[-10000:], "timed_out": True}
                time.sleep(0.05)
            exit_code = channel.recv_exit_status()
            while channel.recv_ready():
                out += channel.recv(65536)
            while channel.recv_stderr_ready():
                err += channel.recv_stderr(65536)
            channel.close()
            return {"exit_code": exit_code, "output": out.decode("utf-8", "replace")[-50000:],
                    "error": err.decode("utf-8", "replace")[-10000:], "timed_out": False}
        finally:
            ssh.close()

    def _run_jump(self, target: Dict[str, Any], command: str, timeout: int) -> Dict[str, Any]:
        """跳板机通道：交互式 Shell + 结束标记回显。"""
        detail = target["_asset"]
        protocol = "ssh"
        protocols = detail.get("permed_protocols") or []
        if protocols:
            protocol = protocols[0].get("name", protocol)
        token = self._client.create_connection_token(
            asset_id=detail["id"], account_alias=target["alias"], protocol=protocol, connect_method="ssh_client"
        )
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self._ssh_host, port=self._settings.ssh_port, username="JMS-" + token["id"],
                    password=token["value"], timeout=15, allow_agent=False, look_for_keys=False)
        try:
            channel = ssh.invoke_shell(width=400, height=100)
            channel.settimeout(1)
            self._drain_idle(channel, 20)
            clean_command = command.strip().rstrip(";")
            channel.send('%s ; echo "%s$?"\n' % (clean_command, DONE_MARKER))
            buffer = self._read_until_exit(channel, timeout)
            return self._parse_shell_output(buffer, timeout)
        finally:
            ssh.close()

    def _drain_idle(self, channel: Any, timeout: int) -> str:
        """等待 Shell 就绪：读取直至输出空闲。"""
        deadline = time.time() + timeout
        last_data = time.time()
        buffer = b""
        while time.time() < deadline:
            if channel.recv_ready():
                buffer += channel.recv(65536)
                last_data = time.time()
            elif time.time() - last_data > 1.0 and buffer:
                break
            else:
                time.sleep(0.05)
        return buffer.decode("utf-8", "replace")

    def _read_until_exit(self, channel: Any, timeout: int) -> str:
        """读取直至出现结束标记；超时时发送 Ctrl-C 并返回已收数据。"""
        deadline = time.time() + timeout
        buffer = b""
        while time.time() < deadline:
            if channel.recv_ready():
                buffer += channel.recv(65536)
            elif _EXIT_PATTERN.search(strip_ansi(buffer.decode("utf-8", "replace"))):
                break
            else:
                time.sleep(0.05)
        if not _EXIT_PATTERN.search(strip_ansi(buffer.decode("utf-8", "replace"))):
            try:
                channel.send("\x03")
                time.sleep(0.3)
                while channel.recv_ready():
                    buffer += channel.recv(65536)
            except Exception:
                pass
        return buffer.decode("utf-8", "replace")

    def _parse_shell_output(self, buffer: str, timeout: int) -> Dict[str, Any]:
        """从交互式输出中提取退出码与命令输出。"""
        clean = strip_ansi(buffer)
        echo_index = clean.rfind(DONE_MARKER + "$?")
        body = clean[echo_index + len(DONE_MARKER) + 3:] if echo_index >= 0 else clean
        match = _EXIT_PATTERN.search(body)
        if not match:
            return {"exit_code": None, "output": ServerCLI._filter_banner(clean)[-20000:],
                    "error": "", "timed_out": True}
        output = ServerCLI._filter_banner(body[:match.start()])
        return {"exit_code": int(match.group(1)), "output": output[-50000:], "error": "", "timed_out": False}

    @staticmethod
    def _filter_banner(text: str) -> str:
        """剔除跳板机连接提示与空行噪声。"""
        lines = [line.rstrip() for line in text.split("\n")]
        kept = [line for line in lines if not _BANNER.match(line.strip())]
        return "\n".join(kept).strip("\n")

    # ------------------------------------------------------------------ 诊断组合

    def get_overview(self, server: str = "", timeout: Optional[int] = None) -> Dict[str, Any]:
        """一次性采集 CPU/内存/磁盘/负载/进程概览。"""
        effective = timeout or max(self._settings.command_timeout, 20)
        commands = [
            'echo "__SEC_UPTIME__" ; uptime',
            'echo "__SEC_MEM__" ; free -m',
            'echo "__SEC_DISK__" ; df -hP -x tmpfs -x devtmpfs',
            'echo "__SEC_LOAD__" ; vmstat 1 2 | tail -n 2',
            'echo "__SEC_CPUTOP__" ; ps aux --sort=-%cpu | head -n 8',
            'echo "__SEC_MEMTOP__" ; ps aux --sort=-%mem | head -n 8',
        ]
        result = self.run_command(" ; ".join(commands), server, effective + 10)
        sections = self._split_sections(result.get("output", ""))
        memory = self._parse_free(sections.get("mem", ""))
        disks = self._parse_df(sections.get("disk", ""))
        return {
            "server": result.get("server"),
            "uptime": sections.get("uptime", "").strip(),
            "memory_mb": memory,
            "disks": disks,
            "vmstat": sections.get("load", "").strip(),
            "top_cpu_processes": sections.get("cputop", "").strip(),
            "top_mem_processes": sections.get("memtop", "").strip(),
            "timed_out": result.get("timed_out", False),
        }

    @staticmethod
    def _split_sections(output: str) -> Dict[str, str]:
        """按 __SEC_XXX__ 标记切分输出。"""
        sections: Dict[str, str] = {}
        current = None
        for line in output.split("\n"):
            match = re.match(r"^__(\w+)__$", line.strip())
            if match:
                current = match.group(1).lower()
                sections[current] = ""
            elif current:
                sections[current] = (sections[current] + "\n" + line).strip("\n")
        return sections

    @staticmethod
    def _parse_free(text: str) -> Dict[str, Any]:
        """解析 free -m 输出。"""
        match = re.search(r"Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", text)
        if not match:
            return {"raw": text}
        total, used, free_, shared, buff, available = [int(g) for g in match.groups()]
        swap = re.search(r"Swap:\s+(\d+)\s+(\d+)\s+(\d+)", text)
        return {
            "total_mb": total, "used_mb": used, "free_mb": free_, "buff_cache_mb": buff,
            "available_mb": available, "used_percent": round(used * 100.0 / total, 1) if total else None,
            "swap_total_mb": int(swap.group(1)) if swap else 0,
            "swap_used_mb": int(swap.group(2)) if swap else 0,
        }

    @staticmethod
    def _parse_df(text: str) -> List[Dict[str, str]]:
        """解析 df -hP 输出。"""
        rows = []
        for line in text.split("\n"):
            parts = line.split()
            if len(parts) >= 6 and parts[-2].endswith("%") and not line.startswith("Filesystem"):
                rows.append({"filesystem": parts[0], "size": parts[1], "used": parts[2],
                             "avail": parts[3], "capacity": parts[4], "mount": parts[5]})
        return rows

    def read_log(self, server: str, path: str, lines: int = 200, keyword: str = "") -> Dict[str, Any]:
        """读取服务器日志文件尾部，可按关键字过滤。

        :param path: 日志绝对路径
        :param lines: 返回尾部行数
        :param keyword: 可选关键字过滤（不区分大小写）
        """
        if not path.startswith("/"):
            raise ServerError("日志路径必须为绝对路径")
        path_q = _quote(path)
        if keyword:
            command = "grep -in -- %s %s | tail -n %d" % (_quote(keyword), path_q, max(1, min(lines, 2000)))
        else:
            command = "tail -n %d %s" % (max(1, min(lines, 2000)), path_q)
        return self.run_command(command, server)

    def service_status(self, server: str, service: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """查询 systemd 服务状态。"""
        if not _NAME_OK.match(service):
            raise ServerError("服务名不合法: %r" % service)
        return self.run_command(
            "systemctl status %s --no-pager -l ; systemctl is-active %s" % (service, service), server, timeout
        )

    def list_processes(self, server: str = "", keyword: str = "", sort: str = "cpu", limit: int = 20) -> Dict[str, Any]:
        """查看进程列表，可按 CPU/内存排序或按关键字过滤。"""
        limit = max(1, min(limit, 100))
        if keyword:
            command = "ps aux | grep -i -- %s | grep -v grep | head -n %d" % (_quote(keyword), limit)
        else:
            sort_key = {"cpu": "-%cpu", "mem": "-%mem"}.get(sort, "-%cpu")
            command = "ps aux --sort=%s | head -n %d" % (sort_key, limit + 1)
        return self.run_command(command, server)
