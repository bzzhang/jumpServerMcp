"""JumpServer API 客户端。

负责：账号认证（换取 Bearer Token）、查询授权数据库资产、创建数据库连接 Token。
数据库查询本身不通过 REST API，而是通过 KoKo 的 SSH 通道完成（见 db_cli.py）。
"""

import time
from typing import Any, Dict, List, Optional

import requests

from config import Settings


class JumpServerError(RuntimeError):
    """JumpServer 接口调用异常。"""


class JumpServerClient:
    """JumpServer REST API 客户端，自动维护 Bearer Token。"""

    def __init__(self, settings: Settings) -> None:
        """
        :param settings: MCP 服务配置，包含跳板机地址与账号密码
        """
        self._settings = settings
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._token_expire_at: float = 0.0
        self._org_id: Optional[str] = settings.org_id

    @property
    def base_url(self) -> str:
        """跳板机根地址。"""
        return self._settings.jumpserver_url

    def _headers(self) -> Dict[str, str]:
        """构造带认证与组织信息的请求头。"""
        headers = {"Authorization": "Bearer " + (self._token or ""), "Accept": "application/json"}
        if self._org_id:
            headers["X-JMS-ORG"] = self._org_id
        return headers

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """统一请求入口：认证过期时自动重新登录并重试一次。"""
        url = self.base_url + path
        kwargs.setdefault("timeout", 20)
        if not self._token:
            self.authenticate()
        response = self._session.request(method, url, headers=self._headers(), **kwargs)
        if response.status_code == 401:
            self.authenticate()
            response = self._session.request(method, url, headers=self._headers(), **kwargs)
        if not response.ok:
            raise JumpServerError(
                "JumpServer 接口调用失败: %s %s -> HTTP %s %s"
                % (method, path, response.status_code, response.text[:500])
            )
        return response

    def authenticate(self) -> str:
        """使用用户名密码换取 API Bearer Token，并缓存至过期前 5 分钟。"""
        response = self._session.post(
            self.base_url + "/api/v1/authentication/tokens/",
            json={"username": self._settings.jumpserver_username, "password": self._settings.jumpserver_password},
            timeout=20,
        )
        if not response.ok:
            raise JumpServerError("JumpServer 登录失败: HTTP %s %s" % (response.status_code, response.text[:500]))
        data = response.json()
        self._token = data["token"]
        self._token_expire_at = time.time() + 3500
        if not self._org_id:
            try:
                current = self._session.get(
                    self.base_url + "/api/v1/orgs/orgs/current/",
                    headers={"Authorization": "Bearer " + self._token},
                    timeout=20,
                ).json()
                self._org_id = current.get("id")
            except Exception:
                self._org_id = None
        return self._token

    def ensure_token(self) -> None:
        """确保当前 API Token 有效。"""
        if not self._token or time.time() >= self._token_expire_at:
            self.authenticate()

    def list_database_assets(self) -> List[Dict[str, Any]]:
        """列出当前账号被授权的数据库资产。"""
        response = self._request("GET", "/api/v1/perms/users/self/assets/?limit=1000")
        assets = response.json().get("results", [])
        return [a for a in assets if str(a.get("category", {}).get("value", "")) == "database"]

    def get_asset_detail(self, asset_id: str) -> Dict[str, Any]:
        """获取单个数据库资产详情（含可用账号与协议）。"""
        return self._request("GET", "/api/v1/perms/users/self/assets/%s/" % asset_id).json()

    def create_connection_token(
        self,
        asset_id: str,
        account_alias: str,
        protocol: str = "mysql",
        connect_method: str = "ssh_client",
    ) -> Dict[str, Any]:
        """创建数据库连接 Token（一次性凭证，用于 SSH 登录 KoKo 数据库 CLI）。"""
        payload = {
            "asset": asset_id,
            "account": account_alias,
            "protocol": protocol,
            "input_username": "",
            "input_secret": "",
            "connect_method": connect_method,
            "connect_options": {},
        }
        return self._request("POST", "/api/v1/authentication/connection-token/", json=payload).json()
