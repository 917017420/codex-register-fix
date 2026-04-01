"""
OAuth 后置会话复用辅助模块
仅负责在注册/验证完成后，复用已有会话落地到 ChatGPT 并提取 session/access token。
"""

from dataclasses import dataclass, field
import base64
import json
import random
import re
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class FlowState:
    """OpenAI Auth/Registration 流程中的页面状态。"""

    page_type: str = ""
    continue_url: str = ""
    method: str = "GET"
    current_url: str = ""
    source: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


def normalize_page_type(value: Optional[str]) -> str:
    """将 page.type 归一化为 snake_case。"""
    return str(value or "").strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")


def normalize_flow_url(url: Optional[str], auth_base: str = "https://auth.openai.com") -> str:
    """将 continue_url / payload.url 归一化为绝对 URL。"""
    value = str(url or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        return f"https:{value}"
    if value.startswith("/"):
        return f"{auth_base.rstrip('/')}{value}"
    return value


def infer_page_type_from_url(url: Optional[str]) -> str:
    """从 URL 推断 page_type。"""
    if not url:
        return ""

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = parsed.query or ""

    if "code=" in query:
        return "oauth_callback"
    if "chatgpt.com" in host and "/api/auth/callback/" in path:
        return "callback"
    if "create-account/password" in path:
        return "create_account_password"
    if "email-verification" in path or "email-otp" in path:
        return "email_otp_verification"
    if "about-you" in path:
        return "about_you"
    if "log-in/password" in path:
        return "login_password"
    if "sign-in-with-chatgpt" in path and "consent" in path:
        return "consent"
    if "workspace" in path and "select" in path:
        return "workspace_selection"
    if "organization" in path and "select" in path:
        return "organization_selection"
    if "add-phone" in path:
        return "add_phone"
    if "callback" in path:
        return "callback"
    if "chatgpt.com" in host and path in {"", "/"}:
        return "chatgpt_home"
    if path:
        return normalize_page_type(path.strip("/").replace("/", "_"))
    return ""


def extract_flow_state(
    data: Optional[Dict[str, Any]] = None,
    current_url: str = "",
    auth_base: str = "https://auth.openai.com",
    default_method: str = "GET",
) -> FlowState:
    """从响应 JSON 或 URL 提取统一的流程状态。"""
    raw = data if isinstance(data, dict) else {}
    page = raw.get("page") or {}
    payload = page.get("payload") or {}

    continue_url = normalize_flow_url(
        raw.get("continue_url") or payload.get("url") or "",
        auth_base=auth_base,
    )
    effective_current_url = continue_url if raw and continue_url else current_url
    current = normalize_flow_url(effective_current_url or continue_url, auth_base=auth_base)
    page_type = normalize_page_type(page.get("type")) or infer_page_type_from_url(continue_url or current)
    method = str(raw.get("method") or payload.get("method") or default_method or "GET").upper()

    return FlowState(
        page_type=page_type,
        continue_url=continue_url,
        method=method,
        current_url=current,
        source="api" if raw else "url",
        payload=payload if isinstance(payload, dict) else {},
        raw=raw,
    )


def describe_flow_state(state: FlowState) -> str:
    """生成简短状态描述，用于日志。"""
    target = state.continue_url or state.current_url or "-"
    return f"page={state.page_type or '-'} method={state.method or '-'} next={target[:80]}..."


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    """解析 JWT payload。"""
    try:
        parts = (token or "").split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def extract_chrome_full_version(user_agent: str) -> str:
    """从 UA 中提取完整 Chrome 版本。"""
    if not user_agent:
        return ""
    match = re.search(r"Chrome/([0-9.]+)", user_agent)
    return match.group(1) if match else ""


def _registrable_domain(hostname: Optional[str]) -> str:
    """粗略提取可注册域名。"""
    if not hostname:
        return ""
    host = hostname.split(":")[0].strip(".").lower()
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def infer_sec_fetch_site(url: str, referer: Optional[str] = None, navigation: bool = False) -> str:
    """根据目标 URL 和 Referer 推断 Sec-Fetch-Site。"""
    if not referer:
        return "none" if navigation else "same-origin"

    try:
        target = urlparse(url or "")
        source = urlparse(referer or "")

        if not target.scheme or not target.netloc or not source.netloc:
            return "none" if navigation else "same-origin"
        if (target.scheme, target.netloc) == (source.scheme, source.netloc):
            return "same-origin"
        if _registrable_domain(target.hostname) == _registrable_domain(source.hostname):
            return "same-site"
    except Exception:
        pass

    return "cross-site"


def build_sec_ch_ua_full_version_list(sec_ch_ua: str, chrome_full_version: str) -> str:
    """根据 sec-ch-ua 生成 sec-ch-ua-full-version-list。"""
    if not sec_ch_ua or not chrome_full_version:
        return ""

    entries = []
    for brand, version in re.findall(r'"([^"]+)";v="([^"]+)"', sec_ch_ua):
        full_version = chrome_full_version if brand in {"Chromium", "Google Chrome"} else f"{version}.0.0.0"
        entries.append(f'"{brand}";v="{full_version}"')
    return ", ".join(entries)


def build_browser_headers(
    *,
    url: str,
    user_agent: str,
    sec_ch_ua: Optional[str] = None,
    chrome_full_version: Optional[str] = None,
    accept: Optional[str] = None,
    accept_language: str = "en-US,en;q=0.9",
    referer: Optional[str] = None,
    origin: Optional[str] = None,
    content_type: Optional[str] = None,
    navigation: bool = False,
    fetch_mode: Optional[str] = None,
    fetch_dest: Optional[str] = None,
    fetch_site: Optional[str] = None,
    headed: bool = False,
    extra_headers: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """构造更接近真实 Chrome 的请求头。"""
    chrome_full = chrome_full_version or extract_chrome_full_version(user_agent)
    full_version_list = build_sec_ch_ua_full_version_list(sec_ch_ua or "", chrome_full)

    headers = {
        "User-Agent": user_agent or "Mozilla/5.0",
        "Accept-Language": accept_language,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
    }

    if accept:
        headers["Accept"] = accept
    if referer:
        headers["Referer"] = referer
    if origin:
        headers["Origin"] = origin
    if content_type:
        headers["Content-Type"] = content_type
    if sec_ch_ua:
        headers["sec-ch-ua"] = sec_ch_ua
    if chrome_full:
        headers["sec-ch-ua-full-version"] = f'"{chrome_full}"'
        headers["sec-ch-ua-platform-version"] = '"15.0.0"'
    if full_version_list:
        headers["sec-ch-ua-full-version-list"] = full_version_list

    if navigation:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Cache-Control"] = "max-age=0"
    else:
        headers["Sec-Fetch-Dest"] = fetch_dest or "empty"
        headers["Sec-Fetch-Mode"] = fetch_mode or "cors"

    headers["Sec-Fetch-Site"] = fetch_site or infer_sec_fetch_site(url, referer, navigation=navigation)

    if headed:
        headers.setdefault("Priority", "u=0, i" if navigation else "u=1, i")
        headers.setdefault("DNT", "1")
        headers.setdefault("Sec-GPC", "1")

    if extra_headers:
        for key, value in extra_headers.items():
            if value is not None:
                headers[key] = str(value)

    return headers


class SessionReuseClient:
    """复用注册完成后的会话，提取 ChatGPT session/access token。"""

    def __init__(
        self,
        session,
        *,
        device_id: str = "",
        browser_mode: str = "protocol",
        user_agent: str = "",
        sec_ch_ua: str = "",
        chrome_full_version: str = "",
        accept_language: str = "en-US,en;q=0.9",
        base: str = "https://chatgpt.com",
        auth_base: str = "https://auth.openai.com",
        logger: Optional[Callable[[str], None]] = None,
    ):
        self.session = session
        self.device_id = str(device_id or "").strip()
        self.browser_mode = str(browser_mode or "protocol").strip().lower()
        self.user_agent = user_agent or "Mozilla/5.0"
        self.sec_ch_ua = sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"'
        self.chrome_full_version = chrome_full_version or extract_chrome_full_version(self.user_agent) or "131.0.0.0"
        self.accept_language = accept_language
        self.base = base.rstrip("/")
        self.auth_base = auth_base.rstrip("/")
        self.logger = logger

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger(message)

    def _browser_pause(self, low: float = 0.05, high: float = 0.15, headed_low: float = 0.18, headed_high: float = 0.45) -> None:
        if self.browser_mode == "headed":
            time.sleep(random.uniform(headed_low, headed_high))
        elif self.browser_mode == "headless":
            time.sleep(random.uniform(low, high))

    def _headers(
        self,
        url: str,
        *,
        accept: str,
        referer: Optional[str] = None,
        origin: Optional[str] = None,
        content_type: Optional[str] = None,
        navigation: bool = False,
        fetch_mode: Optional[str] = None,
        fetch_dest: Optional[str] = None,
        fetch_site: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        return build_browser_headers(
            url=url,
            user_agent=self.user_agent,
            sec_ch_ua=self.sec_ch_ua,
            chrome_full_version=self.chrome_full_version,
            accept=accept,
            accept_language=self.accept_language,
            referer=referer,
            origin=origin,
            content_type=content_type,
            navigation=navigation,
            fetch_mode=fetch_mode,
            fetch_dest=fetch_dest,
            fetch_site=fetch_site,
            headed=self.browser_mode == "headed",
            extra_headers=extra_headers,
        )

    def _state_requires_navigation(self, state: FlowState) -> bool:
        method = (state.method or "GET").upper()
        if method != "GET":
            return False
        if (
            state.source == "api"
            and state.current_url
            and state.page_type not in {"login_password", "email_otp_verification"}
        ):
            return True
        if state.page_type == "external_url" and state.continue_url:
            return True
        if state.continue_url and state.continue_url != state.current_url:
            return True
        return False

    def _follow_flow_state(self, state: FlowState, referer: Optional[str] = None) -> Tuple[bool, Any]:
        """跟随 continue_url，将注册会话真正落地到 ChatGPT。"""
        target_url = state.continue_url or state.current_url
        if not target_url:
            return False, "缺少可跟随的 continue_url"

        try:
            self._browser_pause()
            response = self.session.get(
                target_url,
                headers=self._headers(
                    target_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer,
                    navigation=True,
                    extra_headers={"oai-device-id": self.device_id or None},
                ),
                allow_redirects=True,
                timeout=30,
            )
            final_url = str(response.url)
            content_type = (response.headers.get("content-type", "") or "").lower()

            if "application/json" in content_type:
                try:
                    next_state = extract_flow_state(
                        data=response.json(),
                        current_url=final_url,
                        auth_base=self.auth_base,
                    )
                except Exception:
                    next_state = extract_flow_state(current_url=final_url, auth_base=self.auth_base)
            else:
                next_state = extract_flow_state(current_url=final_url, auth_base=self.auth_base)

            self._log(f"continue_url 落地完成: {final_url[:120]}...")
            self._log(f"落地状态: {describe_flow_state(next_state)}")
            return True, next_state
        except Exception as exc:
            return False, f"注册回调落地失败: {exc}"

    def _get_cookie_value(self, name: str, domain_hint: Optional[str] = None) -> str:
        jar = getattr(self.session.cookies, "jar", None)
        if jar is None:
            try:
                return str(self.session.cookies.get(name) or "").strip()
            except Exception:
                return ""

        for cookie in list(jar):
            if getattr(cookie, "name", "") != name:
                continue
            if domain_hint and domain_hint not in (getattr(cookie, "domain", "") or ""):
                continue
            return str(getattr(cookie, "value", "") or "").strip()
        return ""

    def get_next_auth_session_token(self) -> str:
        """获取 ChatGPT next-auth session cookie。"""
        return self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")

    def fetch_chatgpt_session(self) -> Tuple[bool, Any]:
        """请求 ChatGPT /api/auth/session。"""
        session_url = f"{self.base}/api/auth/session"
        try:
            self._browser_pause()
            response = self.session.get(
                session_url,
                headers=self._headers(
                    session_url,
                    accept="application/json",
                    referer=f"{self.base}/",
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
        except Exception as exc:
            return False, f"/api/auth/session 异常: {exc}"

        if response.status_code != 200:
            return False, f"/api/auth/session -> HTTP {response.status_code}"

        try:
            data = response.json()
        except Exception as exc:
            return False, f"/api/auth/session 返回非 JSON: {exc}"

        if not str(data.get("accessToken") or "").strip():
            return False, "/api/auth/session 未返回 accessToken"
        return True, data

    def reuse_session_and_get_tokens(self, state: Optional[FlowState]) -> Tuple[bool, Any]:
        """复用注册后的同一会话，直接提取 access token。"""
        current_state = state or FlowState()
        self._log("开始复用注册会话提取 Token...")

        if current_state.page_type == "external_url" or self._state_requires_navigation(current_state):
            ok, followed = self._follow_flow_state(
                current_state,
                referer=current_state.current_url or f"{self.auth_base}/about-you",
            )
            if not ok:
                return False, followed
            current_state = followed
        else:
            self._log("注册回调已落地，跳过额外跟随")

        session_cookie = self.get_next_auth_session_token()
        if not session_cookie:
            return False, "缺少 __Secure-next-auth.session-token，注册回调可能未落地"

        ok, session_or_error = self.fetch_chatgpt_session()
        if not ok:
            return False, session_or_error

        session_data = session_or_error
        access_token = str(session_data.get("accessToken") or "").strip()
        session_token = str(session_data.get("sessionToken") or session_cookie or "").strip()
        user = session_data.get("user") or {}
        account = session_data.get("account") or {}
        jwt_payload = decode_jwt_payload(access_token)
        auth_payload = jwt_payload.get("https://api.openai.com/auth") or {}

        account_id = (
            str(account.get("id") or "").strip()
            or str(auth_payload.get("chatgpt_account_id") or "").strip()
        )
        user_id = (
            str(user.get("id") or "").strip()
            or str(auth_payload.get("chatgpt_user_id") or "").strip()
            or str(auth_payload.get("user_id") or "").strip()
        )

        normalized = {
            "access_token": access_token,
            "session_token": session_token,
            "account_id": account_id,
            "workspace_id": account_id,
            "user_id": user_id,
            "email": str(user.get("email") or "").strip(),
            "auth_provider": session_data.get("authProvider"),
            "expires": session_data.get("expires"),
            "user": user,
            "account": account,
            "raw_session": session_data,
        }

        self._log("已成功提取 accessToken")
        if account_id:
            self._log(f"Account ID: {account_id}")
        if user_id:
            self._log(f"User ID: {user_id}")
        return True, normalized
