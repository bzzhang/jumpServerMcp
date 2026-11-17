"""基于跳板机（JumpServer）查询数据库的 MCP 服务。

启动方式：python mcp_server.py （stdio 传输，供 CodeBuddy / Claude Desktop 等客户端接入）
"""

import re
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from config import Settings
from db_cli import DatabaseCLI, QueryError, quote_literal
from jumpserver_client import JumpServerClient
from server_cli import ServerCLI

mcp = FastMCP("vpn-db")
_settings = Settings.from_env()
_js_client = JumpServerClient(_settings)
_cli = DatabaseCLI(_settings, _js_client)
_server_cli = ServerCLI(_settings, _js_client)

_READ_ONLY = re.compile(r"^\s*(select|show|describe|desc|explain|with|use)\b", re.I)


def _check_sql(sql: str, allow_write: bool) -> str:
    """校验 SQL：限制单条语句，默认只允许只读查询。"""
    statement = (sql or "").strip()
    if not statement:
        raise QueryError("SQL 不能为空")
    if ";" in statement.rstrip(";"):
        raise QueryError("一次只允许执行一条 SQL，请拆分后逐条调用")
    if not allow_write and not _READ_ONLY.match(statement):
        raise QueryError("默认仅允许只读 SQL；如需执行写操作请显式设置 allow_write=True")
    return statement


@mcp.tool()
def list_database_assets() -> Dict[str, Any]:
    """列出当前跳板机账号有权访问的所有数据库资产。"""
    try:
        assets = _js_client.list_database_assets()
        return {
            "total": len(assets),
            "assets": [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "address": a.get("address"),
                    "type": (a.get("type") or {}).get("value"),
                    "platform": (a.get("platform") or {}).get("name"),
                    "org_name": a.get("org_name"),
                }
                for a in assets
            ],
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def describe_database_asset(asset: str = "") -> Dict[str, Any]:
    """查看数据库资产的可用协议、账号与默认数据库信息。"""
    try:
        item = _cli.resolve_asset(asset)
        detail = _js_client.get_asset_detail(item["id"])
        return {
            "id": detail.get("id"),
            "name": detail.get("name"),
            "address": detail.get("address"),
            "type": (detail.get("type") or {}).get("value"),
            "database": (detail.get("spec_info") or {}).get("db_name", ""),
            "protocols": [p.get("name") for p in detail.get("permed_protocols", [])],
            "accounts": [
                {
                    "alias": a.get("alias"),
                    "name": a.get("name"),
                    "username": a.get("username"),
                }
                for a in detail.get("permed_accounts", [])
            ],
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def execute_sql(
    sql: str,
    asset: str = "",
    account: str = "",
    database: str = "",
    limit: int = 500,
    allow_write: bool = False,
) -> Dict[str, Any]:
    """通过跳板机在指定数据库资产上执行 SQL。

    :param sql: 要执行的 SQL（单条语句）
    :param asset: 资产 ID 或名称关键字，为空时选择第一个授权资产
    :param account: 账号名称/用户名，为空时优先使用只读账号
    :param database: 执行前要切换的数据库名
    :param limit: 最大返回行数
    :param allow_write: 是否允许 INSERT/UPDATE/DDL 等写操作，默认 False
    :return: 列名、数据行、行数与耗时
    """
    try:
        return _cli.execute(_check_sql(sql, allow_write), asset, account, database, limit).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_databases(asset: str = "", account: str = "") -> Dict[str, Any]:
    """列出当前数据库资产中可访问的数据库。"""
    try:
        return _cli.execute("SHOW DATABASES", asset, account).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_tables(
    database: str,
    asset: str = "",
    account: str = "",
    pattern: str = "",
    limit: int = 500,
) -> Dict[str, Any]:
    """列出指定数据库中的表，可按名称模糊过滤。"""
    try:
        if not database:
            raise QueryError("database 参数不能为空")
        extra = " AND TABLE_NAME LIKE %s" % quote_literal("%" + pattern + "%") if pattern else ""
        sql = (
            "SELECT TABLE_NAME, TABLE_ROWS, TABLE_COMMENT FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = %s%s ORDER BY TABLE_NAME" % (quote_literal(database), extra)
        )
        return _cli.execute(sql, asset, account, limit=limit).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def describe_table(table: str, database: str = "", asset: str = "", account: str = "") -> Dict[str, Any]:
    """查看指定表的字段结构。"""
    try:
        if not table:
            raise QueryError("table 参数不能为空")
        name = ".".join("`%s`" % part.replace("`", "``") for part in table.split("."))
        if "." not in table and database:
            name = "`%s`.`%s`" % (database.replace("`", "``"), table.replace("`", "``"))
        return _cli.execute("DESCRIBE %s" % name, asset, account).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def test_connection(asset: str = "", account: str = "") -> Dict[str, Any]:
    """测试跳板机数据库通道是否可用，返回数据库版本。"""
    try:
        return _cli.execute("SELECT VERSION() AS version", asset, account).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_server_assets() -> Dict[str, Any]:
    """列出可查询的服务器：JumpServer 授权的 SSH 主机资产 + 配置的直连服务器。"""
    try:
        return _server_cli.list_server_assets()
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def run_server_command(
    command: str,
    server: str = "",
    timeout: int = 30,
    allow_advanced: bool = False,
    account: str = "",
) -> Dict[str, Any]:
    """在服务器上执行一条只读诊断命令（查日志、看资源、查进程等）。

    默认仅放行只读白名单命令（cat/tail/grep/ps/free/df/du/top/systemctl status 等）。
    变更类命令（rm、systemctl restart、kill 等）默认拒绝，必须先征得用户明确授权，
    再设置 allow_advanced=True；mkfs、shutdown、rm -rf / 等毁灭性命令永不放行。

    :param command: 单行 shell 命令，如 tail -n 200 /var/log/app.log
    :param server: 服务器名称/地址关键字，为空时选择第一台可查服务器
    :param timeout: 命令超时秒数
    :param allow_advanced: 是否已获用户明确授权执行变更类命令
    :param account: 跳板机资产账号关键字（可选）
    :return: exit_code、output、timed_out、elapsed_ms
    """
    try:
        return _server_cli.run_command(command, server, timeout, allow_advanced, account)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def get_server_overview(server: str = "") -> Dict[str, Any]:
    """采集服务器概览：负载、CPU/内存占用、磁盘使用、CPU/内存占用最高的进程。"""
    try:
        return _server_cli.get_overview(server)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def read_server_log(server: str, path: str, lines: int = 200, keyword: str = "") -> Dict[str, Any]:
    """读取服务器日志文件尾部，可按关键字过滤，用于错误定位。

    :param server: 服务器名称/地址关键字
    :param path: 日志文件绝对路径
    :param lines: 返回尾部行数（最大 2000）
    :param keyword: 可选关键字过滤（不区分大小写）
    """
    try:
        return _server_cli.read_log(server, path, lines, keyword)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def check_service_status(server: str, service: str) -> Dict[str, Any]:
    """查询 systemd 服务运行状态（systemctl status / is-active）。"""
    try:
        return _server_cli.service_status(server, service)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_server_processes(server: str = "", keyword: str = "", sort: str = "cpu", limit: int = 20) -> Dict[str, Any]:
    """查看服务器进程列表，可按 CPU/内存排序或按关键字过滤。

    :param sort: cpu 或 mem，按占用排序
    :param keyword: 进程关键字过滤
    :param limit: 返回进程数量上限
    """
    try:
        return _server_cli.list_processes(server, keyword, sort, limit)
    except Exception as exc:
        return {"error": str(exc)}


if __name__ == "__main__":
    mcp.run(transport="stdio")
