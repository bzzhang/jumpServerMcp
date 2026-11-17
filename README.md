# vpn-db MCP Server

基于 JumpServer 跳板机的 MCP 服务（stdio 传输），提供两类能力：

1. **数据库查询**：JumpServer REST API 换取 Token -> 创建一次性数据库连接 Token ->
   用 `JMS-<token>` 登录跳板机 SSH（KoKo，2222 端口）-> 在 JumpServer Database CLI 中执行 SQL。
2. **服务器问题定位**：对 JumpServer 授权的 SSH 主机资产（或配置的直连服务器）执行只读诊断命令，
   查 CPU、内存、磁盘、负载、进程、服务状态与日志，辅助 AI 定位线上问题。

数据库与服务器凭据不落本地，全部由跳板机托管；所有操作均经跳板机，保留 JumpServer 审计记录。

## 安装

```bash
cd d:/project/vpn-db-git
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
```

## 接入 MCP 客户端

```json
{
  "mcpServers": {
    "vpn-db": {
      "command": "d:/project/vpn-db-git/.venv/Scripts/python.exe",
      "args": ["d:/project/vpn-db-git/mcp_server.py"],
      "env": {
        "JUMPSERVER_URL": "jumpServer 地址",
        "JUMPSERVER_USERNAME": "登录名",
        "JUMPSERVER_PASSWORD": "登录密码"
      }
    }
  }
}
```

## 工具

### 数据库

| 工具 | 说明 |
|------|------|
| `list_database_assets` | 列出授权的 database 类资产 |
| `describe_database_asset` | 查看协议、账号、默认库 |
| `test_connection` | 用 `SELECT VERSION()` 测试通道 |
| `execute_sql` | 执行单条 SQL；默认只读，`allow_write=True` 才允许写操作 |
| `list_databases` / `list_tables` / `describe_table` | 库、表、表结构 |

### 服务器诊断

| 工具 | 说明 |
|------|------|
| `list_server_assets` | 列出可查服务器（JumpServer 主机资产 + 直连配置） |
| `get_server_overview` | 负载、CPU/内存、磁盘、占用最高的进程，一次采集 |
| `run_server_command` | 执行单条只读诊断命令 |
| `read_server_log` | 读日志尾部，可按关键字过滤（定位报错） |
| `check_service_status` | systemctl status / is-active |
| `list_server_processes` | 进程列表，按 CPU/内存排序或按关键字过滤 |

常用入参：`asset`/`server`（资产 ID 或名称关键字，默认第一个）、`account`、`database`、`limit`。

## 安全策略（服务器命令）

1. **只读白名单**：`cat/tail/head/grep/awk/find/ls/ps/top/free/df/du/vmstat/iostat/netstat/ss/
   lsof/journalctl/dmesg/systemctl status/docker ps/kubectl get` 等查询命令默认放行，
   支持管道组合（每段都需在白名单内）。
2. **变更类命令默认拒绝**：`rm/mv/kill/systemctl restart/docker rm/输出重定向/后台执行` 等
   必须先征得用户明确同意，再设置 `allow_advanced=True` 才放行。
3. **毁灭性命令永不放行**：`mkfs`、`dd of=/dev/*`、`shutdown/reboot`、`rm -rf /`、fork 炸弹等
   即使授权也被拦截。
4. 其他限制：仅单行命令、禁止命令替换（`$()`、反引号）、路径与关键字经 shell 转义防注入。
5. `find -delete`、`sed -i`、`curl -d`、`awk system()` 等隐式变更用法按参数级别拦截。

> 说明：该策略为客户端前置防线（命令发出前校验），权限边界仍以服务器系统权限与 JumpServer 审计为准。

## 服务器资产接入

- **推荐**：由 JumpServer 管理员将 Linux 服务器以 SSH 协议授权给本账号（资产分类 host），
  工具会自动创建一次性连接 Token 经跳板机登录执行。
- **备用**：若暂时无法授权，可在 `SERVER_DIRECT_SSH` 配置直连服务器（JSON 数组），例如：

```json
SERVER_DIRECT_SSH=[{"name":"app1","host":"192.168.1.10","port":22,"username":"ops","password":"xxx"}]
```

## 安全说明

- 数据库默认只读，写操作必须显式传 `allow_write=True`；服务器命令默认只读，变更需 `allow_advanced=True`。
- 连接 Token 一次性有效（约 1 小时过期），每次查询自动新建并关闭 SSH 连接。

## 故障排查

- `Authentication failed`：确认跳板机账号密码，以及 `JUMPSERVER_SSH_PORT`（默认 2222）。
- `没有授权的数据库资产` / `没有可查询的服务器`：检查该账号在 JumpServer 中的资产授权。
- 查询无结果或超时：调大 `DB_COMMAND_TIMEOUT`，或减小 `limit`。
