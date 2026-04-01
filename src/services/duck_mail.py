"""
DuckMail 邮箱服务实现
兼容 DuckMail 的 accounts/token/messages 接口模型
"""

import logging
import random
import re
import string
import time
from datetime import datetime, timezone
from html import unescape
from typing import Any, Dict, List, Optional

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..config.constants import OTP_CODE_PATTERN
from ..core.http_client import HTTPClient, RequestConfig


logger = logging.getLogger(__name__)


class DuckMailService(BaseEmailService):
    """DuckMail 邮箱服务"""

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.DUCK_MAIL, name)

        required_keys = ["base_url"]
        missing_keys = [key for key in required_keys if not (config or {}).get(key)]
        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        default_config = {
            "default_domain": "",
            "api_key": "",
            "api_style": "auto",
            "api_key_header": "",
            "password_length": 12,
            "expires_in": None,
            "timeout": 30,
            "max_retries": 3,
            "proxy_url": None,
        }
        self.config = {**default_config, **(config or {})}
        self.config["base_url"] = str(self.config["base_url"]).rstrip("/")
        self.config["default_domain"] = str(self.config["default_domain"]).strip().lstrip("@")
        self.config["api_style"] = str(self.config.get("api_style") or "auto").strip().lower()
        self.config["api_key_header"] = str(self.config.get("api_key_header") or "").strip()
        self._api_style = self._resolve_api_style()

        # DuckMail 风格接口需要完整邮箱地址，因此必须有默认域名。
        if self._api_style == "duckmail" and not self.config["default_domain"]:
            raise ValueError("duck_mail 缺少 default_domain")

        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(
            proxy_url=self.config.get("proxy_url"),
            config=http_config,
        )

        self._accounts_by_id: Dict[str, Dict[str, Any]] = {}
        self._accounts_by_email: Dict[str, Dict[str, Any]] = {}

    def _resolve_api_style(self) -> str:
        style = self.config.get("api_style", "auto")
        if style in {"duckmail", "yyds"}:
            return style

        header_name = str(self.config.get("api_key_header") or "").lower()
        if header_name == "x-api-key":
            return "yyds"

        base_url = self.config["base_url"].lower()
        if "maliapi.215.im" in base_url or base_url.endswith("/v1") or "/v1/" in base_url:
            return "yyds"

        return "duckmail"

    def _build_headers(
        self,
        token: Optional[str] = None,
        use_api_key: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif use_api_key and self.config.get("api_key"):
            api_key = str(self.config["api_key"]).strip()
            header_name = self.config.get("api_key_header")
            if not header_name:
                header_name = "X-API-Key" if self._api_style == "yyds" else "Authorization"

            if str(header_name).lower() == "authorization":
                headers["Authorization"] = f"Bearer {api_key}"
            else:
                headers[str(header_name)] = api_key

        if extra_headers:
            headers.update(extra_headers)

        return headers

    def _unwrap_data(self, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload

        if "success" in payload:
            if payload.get("success") is False:
                error = str(payload.get("error") or payload.get("message") or "API 返回失败")
                error_code = str(payload.get("errorCode") or "").strip()
                if error_code:
                    raise EmailServiceError(f"{error} ({error_code})")
                raise EmailServiceError(error)
            if "data" in payload:
                return payload.get("data")

        return payload

    def _extract_messages(self, payload: Any) -> List[Dict[str, Any]]:
        data = payload
        if isinstance(data, dict):
            if isinstance(data.get("hydra:member"), list):
                return data.get("hydra:member", [])
            if isinstance(data.get("messages"), list):
                return data.get("messages", [])
        return []

    def _make_request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        use_api_key: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        url = f"{self.config['base_url']}{path}"
        kwargs["headers"] = self._build_headers(
            token=token,
            use_api_key=use_api_key,
            extra_headers=kwargs.get("headers"),
        )

        try:
            response = self.http_client.request(method, url, **kwargs)
            if response.status_code >= 400:
                error_message = f"API 请求失败: {response.status_code}"
                try:
                    error_payload = response.json()
                    error_message = f"{error_message} - {error_payload}"
                except Exception:
                    error_message = f"{error_message} - {response.text[:200]}"
                raise EmailServiceError(error_message)

            try:
                payload = response.json()
            except Exception:
                return {"raw_response": response.text}
            return self._unwrap_data(payload)
        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"请求失败: {method} {path} - {e}")

    def _generate_local_part(self) -> str:
        first = random.choice(string.ascii_lowercase)
        rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=7))
        return f"{first}{rest}"

    def _generate_password(self) -> str:
        length = max(6, int(self.config.get("password_length") or 12))
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choices(alphabet, k=length))

    def _cache_account(self, account_info: Dict[str, Any]) -> None:
        account_id = str(account_info.get("account_id") or account_info.get("service_id") or "").strip()
        email = str(account_info.get("email") or "").strip().lower()

        if account_id:
            self._accounts_by_id[account_id] = account_info
        if email:
            self._accounts_by_email[email] = account_info

    def _get_account_info(self, email: Optional[str] = None, email_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if email_id:
            cached = self._accounts_by_id.get(str(email_id))
            if cached:
                return cached

        if email:
            cached = self._accounts_by_email.get(str(email).strip().lower())
            if cached:
                return cached

        return None

    def _strip_html(self, html_content: Any) -> str:
        if isinstance(html_content, list):
            html_content = "\n".join(str(item) for item in html_content if item)
        text = str(html_content or "")
        return unescape(re.sub(r"<[^>]+>", " ", text))

    def _parse_message_time(self, value: Optional[str]) -> Optional[float]:
        if not value:
            return None
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).astimezone(timezone.utc).timestamp()
        except Exception:
            return None

    def _message_search_text(self, summary: Dict[str, Any], detail: Dict[str, Any]) -> str:
        sender = summary.get("from") or detail.get("from") or {}
        if isinstance(sender, dict):
            sender_text = " ".join(
                str(sender.get(key) or "") for key in ("name", "address")
            ).strip()
        else:
            sender_text = str(sender)

        subject = str(summary.get("subject") or detail.get("subject") or "")
        text_body = str(detail.get("text") or "")
        html_body = self._strip_html(detail.get("html"))
        return "\n".join(part for part in [sender_text, subject, text_body, html_body] if part).strip()

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        request_config = config or {}
        raw_address = str(request_config.get("address") or request_config.get("name") or "").strip()
        local_part = raw_address or self._generate_local_part()
        domain = str(
            request_config.get("default_domain")
            or request_config.get("domain")
            or self.config.get("default_domain")
            or ""
        ).strip().lstrip("@")

        if "@" in local_part:
            local_part, parsed_domain = local_part.split("@", 1)
            if not domain:
                domain = parsed_domain.strip().lstrip("@")

        local_part = local_part.strip() or self._generate_local_part()
        address = f"{local_part}@{domain}" if domain else local_part
        password = self._generate_password()

        payload: Dict[str, Any] = {}
        if self._api_style == "yyds":
            payload["address"] = local_part
            if domain:
                payload["domain"] = domain
        else:
            if not domain:
                raise EmailServiceError("DuckMail 模式需要配置 default_domain 或 domain")
            payload["address"] = address
            payload["password"] = password

        expires_in = request_config.get("expiresIn", request_config.get("expires_in", self.config.get("expires_in")))
        if expires_in is not None:
            payload["expiresIn"] = expires_in

        account_response = self._make_request(
            "POST",
            "/accounts",
            json=payload,
            use_api_key=bool(self.config.get("api_key")),
        )

        account_id = str(account_response.get("id") or "").strip()
        resolved_address = str(account_response.get("address") or "").strip()
        token = str(account_response.get("token") or "").strip()

        if not resolved_address:
            resolved_address = address

        if not token and resolved_address:
            token_payload: Dict[str, Any] = {"address": resolved_address}
            if self._api_style == "duckmail":
                token_payload["password"] = password
            token_response = self._make_request(
                "POST",
                "/token",
                json=token_payload,
            )
            if not account_id:
                account_id = str(token_response.get("id") or "").strip()
            token = str(token_response.get("token") or "").strip()

        if not account_id or not resolved_address or not token:
            raise EmailServiceError("DuckMail 返回数据不完整")

        email_info = {
            "email": resolved_address,
            "service_id": account_id,
            "id": account_id,
            "account_id": account_id,
            "token": token,
            "password": password,
            "created_at": time.time(),
            "raw_account": account_response,
            "api_style": self._api_style,
        }

        self._cache_account(email_info)
        self.update_status(True)
        return email_info

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
        exclude_codes: Optional[set] = None,
    ) -> Optional[str]:
        account_info = self._get_account_info(email=email, email_id=email_id)
        if not account_info:
            logger.warning(f"DuckMail 未找到邮箱缓存: {email}, {email_id}")
            return None

        token = account_info.get("token")
        if not token:
            logger.warning(f"DuckMail 邮箱缺少访问 token: {email}")
            return None

        start_time = time.time()
        seen_message_ids = set()
        excluded = {str(code).strip() for code in (exclude_codes or set()) if str(code).strip()}

        while time.time() - start_time < timeout:
            try:
                response = self._make_request(
                    "GET",
                    "/messages",
                    token=token,
                    params={"page": 1},
                )
                messages = self._extract_messages(response)

                for message in messages:
                    message_id = str(message.get("id") or "").strip()
                    if not message_id or message_id in seen_message_ids:
                        continue

                    created_at = self._parse_message_time(
                        str(message.get("createdAt") or message.get("created_at") or "")
                    )
                    if otp_sent_at and created_at and created_at + 1 < otp_sent_at:
                        continue

                    seen_message_ids.add(message_id)
                    detail = self._make_request(
                        "GET",
                        f"/messages/{message_id}",
                        token=token,
                    )

                    content = self._message_search_text(message, detail)
                    if "openai" not in content.lower():
                        continue

                    match = re.search(pattern, content)
                    if match:
                        code = match.group(1)
                        if code in excluded:
                            continue
                        self.update_status(True)
                        return code
            except Exception as e:
                logger.debug(f"DuckMail 轮询验证码失败: {e}")

            time.sleep(3)

        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        return list(self._accounts_by_email.values())

    def delete_email(self, email_id: str) -> bool:
        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info:
            return False

        token = account_info.get("token")
        account_id = account_info.get("account_id") or account_info.get("service_id")
        if not token or not account_id:
            return False

        try:
            self._make_request(
                "DELETE",
                f"/accounts/{account_id}",
                token=token,
            )
            self._accounts_by_id.pop(str(account_id), None)
            self._accounts_by_email.pop(str(account_info.get("email") or "").lower(), None)
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"DuckMail 删除邮箱失败: {e}")
            self.update_status(False, e)
            return False

    def check_health(self) -> bool:
        try:
            request_kwargs: Dict[str, Any] = {
                "use_api_key": bool(self.config.get("api_key")),
            }
            if self._api_style == "duckmail":
                request_kwargs["params"] = {"page": 1}

            self._make_request("GET", "/domains", **request_kwargs)
            self.update_status(True)
            return True
        except Exception as e:
            logger.warning(f"DuckMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False

    def get_email_messages(self, email_id: str, **kwargs) -> List[Dict[str, Any]]:
        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info or not account_info.get("token"):
            return []
        response = self._make_request(
            "GET",
            "/messages",
            token=account_info["token"],
            params={"page": kwargs.get("page", 1)},
        )
        return self._extract_messages(response)

    def get_message_detail(self, email_id: str, message_id: str) -> Optional[Dict[str, Any]]:
        account_info = self._get_account_info(email_id=email_id) or self._get_account_info(email=email_id)
        if not account_info or not account_info.get("token"):
            return None
        return self._make_request(
            "GET",
            f"/messages/{message_id}",
            token=account_info["token"],
        )

    def get_service_info(self) -> Dict[str, Any]:
        return {
            "service_type": self.service_type.value,
            "name": self.name,
            "base_url": self.config["base_url"],
            "default_domain": self.config["default_domain"],
            "api_style": self._api_style,
            "cached_accounts": len(self._accounts_by_email),
            "status": self.status.value,
        }
