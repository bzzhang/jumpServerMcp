"""配置加载：所有参数均可通过环境变量覆盖，便于在 IDE 的 MCP 配置中直接指定。"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _load_dotenv(path: str = ".env") -> None:
    """加载 .env 文件（仅补充尚未设置的环境变量）。"""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


_load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


@dataclass(frozen=True)
class Settings:
    """MCP 服务配置。"""

    jumpserver_url: str
    jumpserver_username: str
    jumpserver_password: str
    org_id: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_port: int = 2222
    command_timeout: int = 30
    max_rows: int = 500
    server_direct: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Settings":
        """从环境变量构建配置。

        SERVER_DIRECT_SSH 为 JSON 数组，作为跳板机主机资产未授权时的直连备用通道，
        例如: [{"name":"app1","host":"192.168.1.10","port":22,"username":"root","password":"xxx"}]
        """
        direct: List[Dict[str, Any]] = []
        raw = os.getenv("SERVER_DIRECT_SSH", "").strip()
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                direct = [item for item in data if isinstance(item, dict) and item.get("host")]
            except (ValueError, TypeError):
                direct = []
        url = os.getenv("JUMPSERVER_URL", "").strip()
        username = os.getenv("JUMPSERVER_USERNAME", "").strip()
        password = os.getenv("JUMPSERVER_PASSWORD", "")
        missing = [name for name, value in
                   (("JUMPSERVER_URL", url), ("JUMPSERVER_USERNAME", username), ("JUMPSERVER_PASSWORD", password))
                   if not value]
        if missing:
            raise RuntimeError(
                "缺少必要配置: %s；请在 MCP 客户端 env 或项目根目录 .env 文件中配置（参见 .env.example）" % ", ".join(missing)
            )
        return cls(
            jumpserver_url=url.rstrip("/"),
            jumpserver_username=username,
            jumpserver_password=password,
            org_id=os.getenv("JUMPSERVER_ORG_ID") or None,
            ssh_host=os.getenv("JUMPSERVER_SSH_HOST") or None,
            ssh_port=int(os.getenv("JUMPSERVER_SSH_PORT", "2222")),
            command_timeout=int(os.getenv("DB_COMMAND_TIMEOUT", "30")),
            max_rows=int(os.getenv("DB_MAX_ROWS", "500")),
            server_direct=direct,
        )
