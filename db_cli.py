"""通过 JumpServer 的 SSH（KoKo）通道执行数据库 SQL。

流程：JumpServer API 创建一次性连接 Token -> 使用 JMS-<token> 登录跳板机 SSH ->
进入 JumpServer Database CLI -> 发送 SQL -> 解析表格输出。
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import paramiko

from config import Settings
from jumpserver_client import JumpServerClient, JumpServerError

logging.getLogger("paramiko").setLevel(logging.WARNING)


class QueryError(RuntimeError):
    """SQL 执行或结果解析失败。"""


@dataclass
class QueryResult:
    """SQL 查询结果。"""

    asset: str
    sql: str
    columns: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    message: str = ""
    elapsed_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为 MCP 工具返回结构。"""
        return {
            "asset": self.asset,
            "sql": self.sql,
            "columns": self.columns,
            "rows": self.rows,
            "row_count": self.row_count,
            "truncated": self.truncated,
            "message": self.message,
            "elapsed_ms": self.elapsed_ms,
        }


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07]*\x07")
_SEPARATOR = re.compile(r"^[-+]+$")
_FOOTER = re.compile(r"^\((\d+)\s+rows?\)$", re.I)


def strip_ansi(text: str) -> str:
    """去除终端 ANSI 颜色、光标控制与退格字符。"""
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_ESCAPE.sub("", text)
    return text.replace("\x08", "")


def parse_table(raw: str, sent_sql: str) -> Tuple[List[str], List[List[str]], str]:
    """把 Database CLI 的表格输出解析为列名与数据行。

    :param raw: SSH 通道原始输出
    :param sent_sql: 实际发送的 SQL（含结尾分号）
    :return: (列名, 数据行, 提示信息)
    """
    clean = strip_ansi(raw)
    index = clean.rfind(sent_sql)
    tail = clean[index + len(sent_sql):] if index >= 0 else clean
    tail = tail.replace("\r\n", "\n").replace("\r", "\n")

    lines: List[str] = []
    for line in tail.split("\n"):
        value = line.rstrip()
        if not value.strip():
            continue
        if re.match(r"^mysql[-=]>", value.strip()):
            continue
        lines.append(value)

    if re.search(r"mysql->\s*$", clean):
        raise QueryError("SQL 未完成（出现续行提示），请检查引号或括号是否闭合")

    errors = [line.strip() for line in lines if line.strip().upper().startswith("ERROR")]
    if errors:
        raise QueryError("数据库返回错误: " + "; ".join(errors))

    separator_index = next((i for i, line in enumerate(lines) if _SEPARATOR.fullmatch(line.strip())), None)
    if separator_index is None or separator_index == 0:
        notice = " ".join(line.strip() for line in lines if not _FOOTER.match(line.strip()))
        return [], [], notice[:2000]

    separator = lines[separator_index].lstrip()
    plus_positions = [m.start() for m in re.finditer(r"\+", separator)]
    starts = [0] + [pos + 1 for pos in plus_positions]
    ends = plus_positions + [len(lines[separator_index])]

    def split_row(line: str) -> List[str]:
        return [line[start:end].strip() for start, end in zip(starts, ends)]

    columns = split_row(lines[separator_index - 1])
    rows: List[List[str]] = []
    for line in lines[separator_index + 1:]:
        if _FOOTER.match(line.strip()):
            break
        rows.append(split_row(line))
    return columns, rows, ""


class DatabaseCLI:
    """基于 JumpServer SSH 通道的数据库查询器。"""

    def __init__(self, settings: Settings, client: JumpServerClient) -> None:
        """
        :param settings: MCP 服务配置
        :param client: JumpServer API 客户端
        """
        self._settings = settings
        self._client = client
        self._ssh_host = settings.ssh_host or urlparse(settings.jumpserver_url).hostname
        if not self._ssh_host:
            raise JumpServerError("无法确定跳板机 SSH 地址，请配置 JUMPSERVER_SSH_HOST")

    def resolve_asset(self, keyword: str = "") -> Dict[str, Any]:
        """按 ID 或名称关键字定位授权数据库资产。"""
        assets = self._client.list_database_assets()
        if not assets:
            raise QueryError("当前账号没有授权的数据库资产")
        if not keyword:
            return assets[0]
        for asset in assets:
            if asset["id"] == keyword or asset.get("name") == keyword:
                return asset
        matched = [a for a in assets if keyword.lower() in str(a.get("name", "")).lower()]
        if len(matched) == 1:
            return matched[0]
        if len(matched) > 1:
            raise QueryError("资产名称匹配到多个结果，请传入更精确的名称或资产 ID: %s" % [a["name"] for a in matched])
        raise QueryError("未找到数据库资产: %s" % keyword)

    def resolve_account(self, asset: Dict[str, Any], keyword: str = "") -> Dict[str, Any]:
        """选择资产账号：优先只读账号，其次第一个授权账号。"""
        detail = self._client.get_asset_detail(asset["id"])
        accounts = detail.get("permed_accounts") or []
        if not accounts:
            raise QueryError("资产 %s 没有可用账号" % asset.get("name"))
        if keyword:
            for account in accounts:
                if keyword in (account.get("alias"), account.get("name"), account.get("username")):
                    return account
            raise QueryError("资产 %s 未授权账号: %s" % (asset.get("name"), keyword))
        for account in accounts:
            label = "%s %s" % (account.get("name", ""), account.get("username", ""))
            if "read" in label.lower():
                return account
        return accounts[0]

    def _open_channel(self, asset: Dict[str, Any], account: Dict[str, Any]) -> Tuple[paramiko.SSHClient, Any]:
        """创建一次性 SSH 连接并等待数据库 CLI 就绪。"""
        protocol = "mysql"
        permed = asset.get("permed_protocols") or []
        if permed:
            protocol = permed[0].get("name", protocol)
        token = self._client.create_connection_token(
            asset_id=asset["id"], account_alias=account["alias"], protocol=protocol, connect_method="ssh_client"
        )
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            self._ssh_host,
            port=self._settings.ssh_port,
            username="JMS-" + token["id"],
            password=token["value"],
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        channel = ssh.invoke_shell(width=400, height=100)
        channel.settimeout(1)
        self._read_until_ready(channel, 20)
        return ssh, channel

    def _read_until_ready(self, channel: Any, timeout: int) -> str:
        """读取直至出现 mysql 提示符。"""
        deadline = time.time() + timeout
        buffer = b""
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            elif buffer and re.search(r"mysql[-=]>\s*$", strip_ansi(buffer.decode("utf-8", "replace")).rstrip()):
                break
            else:
                time.sleep(0.05)
        return buffer.decode("utf-8", "replace")

    def _send_sql(self, channel: Any, sql: str, timeout: int) -> str:
        """发送单条 SQL 并等待执行结果。"""
        sent = sql.strip().rstrip(";") + ";"
        channel.send(sent + "\n")
        deadline = time.time() + timeout
        last_data = time.time()
        buffer = b""
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                last_data = time.time()
            else:
                text = strip_ansi(buffer.decode("utf-8", "replace")).rstrip()
                if buffer and time.time() - last_data > 0.4 and re.search(r"mysql[-=]>\s*$", text):
                    break
                time.sleep(0.05)
        return buffer.decode("utf-8", "replace")

    def execute(
        self,
        sql: str,
        asset_keyword: str = "",
        account_keyword: str = "",
        database: str = "",
        limit: Optional[int] = None,
    ) -> QueryResult:
        """通过跳板机执行 SQL 并返回结构化结果。

        :param sql: 待执行 SQL，多条语句请用分号分隔后逐次调用
        :param asset_keyword: 资产 ID 或名称关键字，为空时选择第一个授权资产
        :param account_keyword: 账号名称/用户名，为空时优先只读账号
        :param database: 可选，执行前切换的数据库名
        :param limit: 可选，最大返回行数，默认使用配置值
        :return: 查询结果（列名、数据行、行数、耗时）
        """
        started = time.time()
        asset = self.resolve_asset(asset_keyword)
        account = self.resolve_account(asset, account_keyword)
        ssh, channel = self._open_channel(asset, account)
        try:
            timeout = self._settings.command_timeout
            if database:
                use_sql = "USE `%s`" % database.replace("`", "``")
                self._send_sql(channel, use_sql, timeout)
            raw = self._send_sql(channel, sql, timeout)
            columns, rows, notice = parse_table(raw, sql.strip().rstrip(";") + ";")
            max_rows = limit or self._settings.max_rows
            truncated = len(rows) > max_rows
            rows = rows[:max_rows]
            count_match = _FOOTER.search(raw)
            row_count = int(count_match.group(1)) if count_match else len(rows)
            return QueryResult(
                asset=str(asset.get("name")),
                sql=sql,
                columns=columns,
                rows=rows,
                row_count=row_count,
                truncated=truncated,
                message=notice,
                elapsed_ms=int((time.time() - started) * 1000),
            )
        finally:
            channel.close()
            ssh.close()


def quote_literal(value: str) -> str:
    """转义 SQL 字符串字面量，避免通过终端拼接 SQL 时注入。"""
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"
