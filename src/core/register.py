"""
注册流程引擎
从 main.py 中提取并重构的注册流程
"""

import re
import json
import time
import logging
import random
import uuid
import secrets
import string
import base64
import urllib.parse
from typing import Optional, Dict, Any, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime

from curl_cffi import requests as cffi_requests

from .openai.oauth import OAuthManager, OAuthStart
from .openai.chatgpt_register_v2 import ChatGPTClient as ChatGPTRegisterClientV2
from .openai.oauth_login_v2 import OAuthLoginConfig, OAuthLoginV2
from .openai.session_reuse_v2 import (
    FlowState,
    SessionReuseClient,
    describe_flow_state,
    extract_flow_state,
)
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    FIRST_NAMES,
    LAST_NAMES,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)
SUPPORTED_BROWSER_MODES = {"protocol", "headless", "headed"}


def _normalize_browser_mode(browser_mode: Optional[str]) -> str:
    """规范化执行模式，未知值回落到 protocol。"""
    mode = str(browser_mode or "protocol").strip().lower()
    return mode if mode in SUPPORTED_BROWSER_MODES else "protocol"


def _make_trace_headers():
    """生成 Datadog APM trace headers（和真实浏览器的 RUM SDK 一致）"""
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": tp, "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
    }


# ============================================================================
# Sentinel Token 生成器 & 辅助函数（从当前项目移植）
# ============================================================================

class SentinelTokenGenerator:
    """Sentinel PoW token 生成器"""
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str):
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    def _get_config(self):
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)",
            time.gmtime(),
        )
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_prop = random.choice([
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ])
        nav_val = f"{nav_prop}-undefined"
        return [
            "1920x1080", now_str, 4294705152, random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None, None, "en-US", "en-US,en", random.random(), nav_val,
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now, self.sid, "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @staticmethod
    def _base64_encode(data):
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        seed = seed if seed is not None else self.requirements_seed
        difficulty = str(difficulty or "0")
        start_time = time.time()
        config = self._get_config()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data


def _fetch_sentinel_challenge(session, device_id, flow="authorize_continue", user_agent=None,
                              sec_ch_ua=None, impersonate=None):
    """获取 Sentinel challenge"""
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    req_body = {"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    kwargs = {"data": json.dumps(req_body), "headers": headers, "timeout": 20}
    if impersonate:
        kwargs["impersonate"] = impersonate
    try:
        resp = session.post("https://sentinel.openai.com/backend-api/sentinel/req", **kwargs)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _build_sentinel_token(session, device_id, flow="authorize_continue", user_agent=None,
                          sec_ch_ua=None, impersonate=None):
    """构建完整的 Sentinel token（含 PoW）"""
    challenge = _fetch_sentinel_challenge(session, device_id, flow=flow,
                                          user_agent=user_agent, sec_ch_ua=sec_ch_ua,
                                          impersonate=impersonate)
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    if not c_value:
        return None
    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()
    return json.dumps(
        {"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow},
        separators=(",", ":"),
    )


def _extract_code_from_url(url: str) -> Optional[str]:
    """从 URL 中提取 authorization code"""
    if not url or "code=" not in url:
        return None
    try:
        return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None


def _token_preview(token: Any, prefix: int = 12) -> str:
    raw = str(token or "").strip()
    if not raw:
        return "missing"
    return f"len={len(raw)}, prefix={raw[:prefix]}..."


def _format_token_snapshot(token_map: Dict[str, Any]) -> str:
    parts = []
    for key in ("access_token", "session_token", "refresh_token", "id_token"):
        parts.append(f"{key}={_token_preview(token_map.get(key, ''))}")
    return ", ".join(parts)


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    email: str = ""
    password: str = ""  # 注册密码
    account_id: str = ""
    workspace_id: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    session_token: str = ""  # 会话令牌
    error_message: str = ""
    logs: list = None
    metadata: dict = None
    source: str = "register"  # 'register' 或 'login'，区分账号来源

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "email": self.email,
            "password": self.password,
            "account_id": self.account_id,
            "workspace_id": self.workspace_id,
            "access_token": self.access_token[:20] + "..." if self.access_token else "",
            "refresh_token": self.refresh_token[:20] + "..." if self.refresh_token else "",
            "id_token": self.id_token[:20] + "..." if self.id_token else "",
            "session_token": self.session_token[:20] + "..." if self.session_token else "",
            "error_message": self.error_message,
            "logs": self.logs or [],
            "metadata": self.metadata or {},
            "source": self.source,
        }


@dataclass
class SignupFormResult:
    """提交注册表单的结果"""
    success: bool
    page_type: str = ""  # 响应中的 page.type 字段
    is_existing_account: bool = False  # 是否为已注册账号
    response_data: Dict[str, Any] = None  # 完整的响应数据
    error_message: str = ""


class _EmailServiceV2Adapter:
    """为 V2 注册状态机适配 old 项目的接码接口。"""

    def __init__(
        self,
        email_service: BaseEmailService,
        email: str,
        email_info: Optional[Dict[str, Any]],
        log_fn: Callable[[str], None],
        used_codes: Optional[set] = None,
    ):
        self.email_service = email_service
        self.email = email
        self.email_info = email_info or {}
        self.log_fn = log_fn
        self.used_codes = used_codes if used_codes is not None else set()

    def wait_for_verification_code(self, email: str, timeout: int = 60, otp_sent_at: Optional[float] = None, exclude_codes=None):
        self.log_fn(f"正在等待邮箱 {email} 的验证码 ({timeout}s)...")
        ignored_codes = set(self.used_codes)
        if exclude_codes:
            ignored_codes.update(str(code).strip() for code in exclude_codes if str(code).strip())
        code = self.email_service.get_verification_code(
            email=self.email,
            email_id=self.email_info.get("service_id"),
            timeout=timeout,
            pattern=OTP_CODE_PATTERN,
            otp_sent_at=otp_sent_at,
            exclude_codes=ignored_codes,
        )
        if code:
            self.used_codes.add(code)
            self.log_fn(f"成功获取验证码: {code}")
        return code


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        browser_mode: str = "protocol",
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            browser_mode: 执行模式（protocol | headless | headed）
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.browser_mode = _normalize_browser_mode(browser_mode)
        self.callback_logger = callback_logger or (lambda msg: logger.info(msg))
        self.task_uuid = task_uuid

        # 创建 HTTP 客户端
        self.http_client = OpenAIHTTPClient(proxy_url=proxy_url)

        # 创建 OAuth 管理器
        settings = get_settings()
        self.oauth_manager = OAuthManager(
            client_id=settings.openai_client_id,
            auth_url=settings.openai_auth_url,
            token_url=settings.openai_token_url,
            redirect_uri=settings.openai_redirect_uri,
            scope=settings.openai_scope,
            proxy_url=proxy_url  # 传递代理配置
        )

        # 状态变量
        self.email: Optional[str] = None
        self.password: Optional[str] = None  # 注册密码
        self.email_info: Optional[Dict[str, Any]] = None
        self.oauth_start: Optional[OAuthStart] = None
        self.session: Optional[cffi_requests.Session] = None
        self.session_token: Optional[str] = None  # 会话令牌
        self.logs: list = []
        self._otp_sent_at: Optional[float] = None  # OTP 发送时间戳
        self._is_existing_account: bool = False  # 是否为已注册账号（用于自动登录）
        self._used_verification_codes: set = set()  # 跨注册/登录阶段去重
        self._otp_continue_url: Optional[str] = None  # OTP 验证后的 continue_url
        self._post_auth_continue_url: Optional[str] = None  # 注册完成后的 continue_url
        self._otp_flow_state: Optional[FlowState] = None  # OTP 验证后的流程状态
        self._post_auth_flow_state: Optional[FlowState] = None  # 创建账户后的流程状态
        self._device_id: Optional[str] = None  # Device ID，所有 API 请求共用
        self._last_oauth_follow_url: Optional[str] = None  # OAuth 跟随后实际落地的 URL
        self._callback_url_from_consent: Optional[str] = None  # 免登录 OAuth 直接拿到的 callback URL
        self._profile_first_name: str = ""
        self._profile_last_name: str = ""
        self._profile_birthdate: str = ""

    def _log(self, message: str, level: str = "info"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # 添加到日志列表
        self.logs.append(log_message)

        # 调用回调函数
        if self.callback_logger:
            self.callback_logger(log_message)

        # 记录到数据库（如果有关联任务）
        if self.task_uuid:
            try:
                with get_db() as db:
                    crud.append_task_log(db, self.task_uuid, log_message)
            except Exception as e:
                logger.warning(f"记录任务日志失败: {e}")

        # 根据级别记录到日志系统
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)

    def _browser_pause(
        self,
        headless_range: Tuple[float, float] = (0.05, 0.15),
        headed_range: Tuple[float, float] = (0.18, 0.45),
    ):
        """为不同执行模式注入轻微节奏差异。"""
        if self.browser_mode == "headed":
            time.sleep(random.uniform(*headed_range))
        elif self.browser_mode == "headless":
            time.sleep(random.uniform(*headless_range))

    def _generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """生成随机密码"""
        return ''.join(secrets.choice(PASSWORD_CHARSET) for _ in range(length))

    def _check_ip_location(self) -> Tuple[bool, Optional[str]]:
        """检查 IP 地理位置"""
        try:
            return self.http_client.check_ip_location()
        except Exception as e:
            self._log(f"检查 IP 地理位置失败: {e}", "error")
            return False, None

    def _create_email(self) -> bool:
        """创建邮箱"""
        try:
            self._log(f"正在创建 {self.email_service.service_type.value} 邮箱...")
            self.email_info = self.email_service.create_email()

            if not self.email_info or "email" not in self.email_info:
                self._log("创建邮箱失败: 返回信息不完整", "error")
                return False

            self.email = self.email_info["email"]
            self._log(f"成功创建邮箱: {self.email}")
            return True

        except Exception as e:
            self._log(f"创建邮箱失败: {e}", "error")
            return False

    def _start_oauth(self) -> bool:
        """开始 OAuth 流程"""
        try:
            self._log("开始 OAuth 授权流程...")
            self.oauth_start = self.oauth_manager.start_oauth()
            self._log(f"OAuth URL 已生成: {self.oauth_start.auth_url[:80]}...")
            return True
        except Exception as e:
            self._log(f"生成 OAuth URL 失败: {e}", "error")
            return False

    def _init_session(self) -> bool:
        """初始化会话"""
        try:
            self.session = self.http_client.session
            return True
        except Exception as e:
            self._log(f"初始化会话失败: {e}", "error")
            return False

    def _get_device_id(self) -> Optional[str]:
        """获取 Device ID"""
        self._browser_pause()
        if not self.oauth_start:
            return None

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if not self.session:
                    self.session = self.http_client.session

                response = self.session.get(
                    self.oauth_start.auth_url,
                    timeout=20
                )
                did = self.session.cookies.get("oai-did")

                if did:
                    self._log(f"Device ID: {did}")
                    self._device_id = did
                    return did

                self._log(
                    f"获取 Device ID 失败: 未返回 oai-did Cookie (HTTP {response.status_code}, 第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )
            except Exception as e:
                self._log(
                    f"获取 Device ID 失败: {e} (第 {attempt}/{max_attempts} 次)",
                    "warning" if attempt < max_attempts else "error"
                )

            if attempt < max_attempts:
                time.sleep(attempt)
                self.http_client.close()
                self.session = self.http_client.session

        return None

    def _check_sentinel(self, did: str) -> Optional[str]:
        """检查 Sentinel 拦截（使用完整 PoW token）"""
        try:
            token = _build_sentinel_token(
                self.session, did,
                flow="authorize_continue",
                user_agent=self._OAUTH_UA,
                impersonate="chrome131",
            )
            if token:
                self._log("Sentinel token 获取成功")
            else:
                self._log("Sentinel token 生成失败", "warning")
            return token

        except Exception as e:
            self._log(f"Sentinel 检查异常: {e}", "warning")
            return None

    def _submit_signup_form(self, did: str, sen_token: Optional[str]) -> SignupFormResult:
        """
        提交注册表单

        Returns:
            SignupFormResult: 提交结果，包含账号状态判断
        """
        self._browser_pause()
        try:
            headers = {
                "referer": "https://auth.openai.com/create-account",
                "origin": "https://auth.openai.com",
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": self._OAUTH_UA,
                "oai-device-id": did,
                "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
            headers.update(_make_trace_headers())

            if sen_token:
                headers["openai-sentinel-token"] = sen_token

            response = self.session.post(
                OPENAI_API_ENDPOINTS["signup"],
                headers=headers,
                json={
                    "username": {"kind": "email", "value": self.email},
                    "screen_hint": "signup",
                },
                allow_redirects=False,
                impersonate="chrome131",
            )

            self._log(f"提交注册表单状态: {response.status_code}")

            if response.status_code != 200:
                # 详细记录 403 响应内容，便于调试
                resp_body = response.text[:500] if response.text else "(empty)"
                server = response.headers.get("server", "")
                content_type = response.headers.get("content-type", "")
                cf_ray = response.headers.get("cf-ray", "")
                cf_mitigated = response.headers.get("cf-mitigated", "")
                self._log(
                    f"注册表单失败头部: server={server}, content-type={content_type}, "
                    f"cf-ray={cf_ray}, cf-mitigated={cf_mitigated}",
                    "warning"
                )
                self._log(f"注册表单失败详情: {resp_body}", "warning")

                # Cloudflare 挑战页特征识别（常见于服务器/机房 IP）
                lowered = (response.text or "").lower()
                if (
                    response.status_code == 403 and
                    (
                        "just a moment" in lowered or
                        "cf-mitigated" in response.headers or
                        "cloudflare" in (server or "").lower()
                    )
                ):
                    self._log(
                        "检测到 Cloudflare 挑战页拦截：当前出口 IP/网络环境可能触发风控",
                        "warning"
                    )
                return SignupFormResult(
                    success=False,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )

            # 解析响应判断账号状态
            try:
                response_data = response.json()
                page_type = response_data.get("page", {}).get("type", "")
                self._log(f"响应页面类型: {page_type}")

                # 判断是否为已注册账号
                is_existing = page_type == OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]

                if is_existing:
                    self._log(f"检测到已注册账号，将自动切换到登录流程")
                    self._is_existing_account = True

                return SignupFormResult(
                    success=True,
                    page_type=page_type,
                    is_existing_account=is_existing,
                    response_data=response_data
                )

            except Exception as parse_error:
                self._log(f"解析响应失败: {parse_error}", "warning")
                # 无法解析，默认成功
                return SignupFormResult(success=True)

        except Exception as e:
            self._log(f"提交注册表单失败: {e}", "error")
            return SignupFormResult(success=False, error_message=str(e))

    def _register_password(self) -> Tuple[bool, Optional[str]]:
        """注册密码"""
        self._browser_pause()
        try:
            # 生成密码
            password = self._generate_password()
            self.password = password  # 保存密码到实例变量
            self._log(f"生成密码: {password}")

            # 提交密码注册
            reg_headers = {
                "referer": "https://auth.openai.com/create-account/password",
                "origin": "https://auth.openai.com",
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": self._OAUTH_UA,
                "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
            if self._device_id:
                reg_headers["oai-device-id"] = self._device_id
            reg_headers.update(_make_trace_headers())

            response = self.session.post(
                OPENAI_API_ENDPOINTS["register"],
                headers=reg_headers,
                json={"password": password, "username": self.email},
                impersonate="chrome131",
            )

            self._log(f"提交密码状态: {response.status_code}")

            if response.status_code != 200:
                error_text = response.text[:500]
                self._log(f"密码注册失败: {error_text}", "warning")

                # 解析错误信息，判断是否是邮箱已注册
                try:
                    error_json = response.json()
                    error_msg = error_json.get("error", {}).get("message", "")
                    error_code = error_json.get("error", {}).get("code", "")

                    # 检测邮箱已注册的情况
                    if "already" in error_msg.lower() or "exists" in error_msg.lower() or error_code == "user_exists":
                        self._log(f"邮箱 {self.email} 可能已在 OpenAI 注册过", "error")
                        # 标记此邮箱为已注册状态
                        self._mark_email_as_registered()
                except Exception:
                    pass

                return False, None

            return True, password

        except Exception as e:
            self._log(f"密码注册失败: {e}", "error")
            return False, None

    def _mark_email_as_registered(self):
        """标记邮箱为已注册状态（用于防止重复尝试）"""
        try:
            with get_db() as db:
                # 检查是否已存在该邮箱的记录
                existing = crud.get_account_by_email(db, self.email)
                if not existing:
                    # 创建一个失败记录，标记该邮箱已注册过
                    crud.create_account(
                        db,
                        email=self.email,
                        password="",  # 空密码表示未成功注册
                        email_service=self.email_service.service_type.value,
                        email_service_id=self.email_info.get("service_id") if self.email_info else None,
                        status="failed",
                        extra_data={"register_failed_reason": "email_already_registered_on_openai"}
                    )
                    self._log(f"已在数据库中标记邮箱 {self.email} 为已注册状态")
        except Exception as e:
            logger.warning(f"标记邮箱状态失败: {e}")

    def _send_verification_code(self) -> bool:
        """发送验证码"""
        self._browser_pause()
        try:
            # 记录发送时间戳
            self._otp_sent_at = time.time()

            otp_send_headers = {
                "referer": "https://auth.openai.com/create-account/password",
                "origin": "https://auth.openai.com",
                "accept": "application/json",
                "user-agent": self._OAUTH_UA,
                "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
            if self._device_id:
                otp_send_headers["oai-device-id"] = self._device_id
            otp_send_headers.update(_make_trace_headers())

            response = self.session.get(
                OPENAI_API_ENDPOINTS["send_otp"],
                headers=otp_send_headers,
                impersonate="chrome131",
            )

            self._log(f"验证码发送状态: {response.status_code}")
            return response.status_code == 200

        except Exception as e:
            self._log(f"发送验证码失败: {e}", "error")
            return False

    def _get_verification_code(self) -> Optional[str]:
        """获取验证码"""
        try:
            self._log(f"正在等待邮箱 {self.email} 的验证码...")

            email_id = self.email_info.get("service_id") if self.email_info else None
            code = self.email_service.get_verification_code(
                email=self.email,
                email_id=email_id,
                timeout=120,
                pattern=OTP_CODE_PATTERN,
                otp_sent_at=self._otp_sent_at,
                exclude_codes=self._used_verification_codes,
            )

            if code:
                self._used_verification_codes.add(code)
                self._log(f"成功获取验证码: {code}")
                return code
            else:
                self._log("等待验证码超时", "error")
                return None

        except Exception as e:
            self._log(f"获取验证码失败: {e}", "error")
            return None

    def _validate_verification_code(self, code: str) -> bool:
        """验证验证码"""
        self._browser_pause()
        try:
            otp_headers = {
                "referer": "https://auth.openai.com/email-verification",
                "origin": "https://auth.openai.com",
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": self._OAUTH_UA,
                "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
            if self._device_id:
                otp_headers["oai-device-id"] = self._device_id
            otp_headers.update(_make_trace_headers())

            response = self.session.post(
                OPENAI_API_ENDPOINTS["validate_otp"],
                headers=otp_headers,
                json={"code": code},
                impersonate="chrome131",
            )

            self._log(f"验证码校验状态: {response.status_code}")

            if response.status_code != 200:
                return False

            # 解析响应，提取 continue_url 以便后续跟随重定向获取完整 cookie
            try:
                resp_data = response.json()
                flow_state = extract_flow_state(
                    data=resp_data,
                    current_url=str(response.url) or "https://auth.openai.com/about-you",
                    auth_base="https://auth.openai.com",
                )
                self._otp_flow_state = flow_state
                self._post_auth_flow_state = flow_state
                continue_url = flow_state.continue_url
                if continue_url:
                    self._otp_continue_url = continue_url
                    self._post_auth_continue_url = continue_url
                    self._log(f"验证码响应状态: {describe_flow_state(flow_state)}")
            except Exception:
                pass

            return True

        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _create_user_account(self) -> bool:
        """创建用户账户"""
        self._browser_pause()
        try:
            for attempt in range(2):
                current_year = datetime.now().year
                user_info = {
                    "name": f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}",
                    "birthdate": f"{random.randint(current_year - 30, current_year - 20):04d}-"
                                 f"{random.randint(1, 12):02d}-"
                                 f"{random.randint(1, 28):02d}",
                }
                self._log(
                    f"生成用户信息: {user_info['name']}, 生日: {user_info['birthdate']}"
                    f"{' (重试)' if attempt > 0 else ''}"
                )

                headers = {
                    "referer": "https://auth.openai.com/about-you",
                    "origin": "https://auth.openai.com",
                    "accept": "application/json",
                    "accept-language": "en-US,en;q=0.9",
                    "content-type": "application/json",
                    "user-agent": self._OAUTH_UA,
                    "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                }
                if self._device_id:
                    headers["oai-device-id"] = self._device_id

                sentinel_token = None
                if self._device_id:
                    sentinel_token = _build_sentinel_token(
                        self.session,
                        self._device_id,
                        flow="authorize_continue",
                        user_agent=self._OAUTH_UA,
                        sec_ch_ua=headers["sec-ch-ua"],
                        impersonate="chrome131",
                    )
                if sentinel_token:
                    headers["openai-sentinel-token"] = sentinel_token
                    self._log("create_account: 已附加 sentinel token")
                else:
                    self._log("create_account: sentinel token 生成失败，降级继续", "warning")

                headers.update(_make_trace_headers())

                response = self.session.post(
                    OPENAI_API_ENDPOINTS["create_account"],
                    headers=headers,
                    json=user_info,
                    impersonate="chrome131",
                )

                self._log(f"账户创建状态: {response.status_code}")

                if response.status_code == 200:
                    break

                body_preview = response.text[:300]
                self._log(f"账户创建失败: {body_preview}", "warning")
                if (
                    response.status_code == 400
                    and "registration_disallowed" in (response.text or "")
                    and attempt == 0
                ):
                    self._log("检测到 registration_disallowed，刷新个人信息与 sentinel 后重试一次", "warning")
                    continue
                return False
            else:
                return False

            # 解析响应中的 continue_url 并跟随重定向，
            # 记录流程状态，后续统一交给 V2 Session Reuse 逻辑处理
            try:
                resp_data = response.json()
                flow_state = extract_flow_state(
                    data=resp_data,
                    current_url=str(response.url) or "https://chatgpt.com/",
                    auth_base="https://auth.openai.com",
                )
                self._post_auth_flow_state = flow_state
                continue_url = flow_state.continue_url
                if continue_url:
                    self._post_auth_continue_url = continue_url
                    self._log(f"create_account 响应状态: {describe_flow_state(flow_state)}")
                else:
                    self._log("create_account 响应中未包含 continue_url", "warning")
            except Exception as e:
                self._log(f"解析 create_account 响应状态失败: {e}", "warning")

            return True

        except Exception as e:
            self._log(f"创建账户失败: {e}", "error")
            return False

    def _visit_consent_page(self) -> bool:
        """注册完成后重新发起 OAuth 授权（不带 prompt=login），
        利用已认证 session 自动走 consent → workspace → callback，
        直接拿到 callback URL 中的 auth code。"""
        import urllib.parse
        from .openai.oauth import (
            _random_state, _pkce_verifier, _sha256_b64url_no_pad,
            OAuthStart,
        )
        from ..config.constants import (
            OAUTH_AUTH_URL, OAUTH_REDIRECT_URI, OAUTH_SCOPE, OAUTH_CLIENT_ID,
        )

        try:
            # 生成新的 PKCE 和 state（不带 prompt=login）
            state = _random_state()
            code_verifier = _pkce_verifier()
            code_challenge = _sha256_b64url_no_pad(code_verifier)

            params = {
                "client_id": OAUTH_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": OAUTH_REDIRECT_URI,
                "scope": OAUTH_SCOPE,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
            }
            auth_url = f"{OAUTH_AUTH_URL}?{urllib.parse.urlencode(params)}"
            self._log("发起新 OAuth 授权（无 prompt=login）...")

            # 手动跟随重定向，寻找 callback URL 中的 code
            current_url = auth_url
            max_redirects = 15
            self._callback_url_from_consent = None
            self._last_oauth_follow_url = auth_url

            for i in range(max_redirects):
                response = self.session.get(
                    current_url,
                    headers={
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "upgrade-insecure-requests": "1",
                    },
                    allow_redirects=False,
                    timeout=30,
                )
                self._last_oauth_follow_url = str(response.url) or current_url

                location = response.headers.get("Location", "")

                # 检查当前 URL 或 Location 是否包含 code
                for url_to_check in [location, current_url]:
                    if "code=" in url_to_check and "state=" in url_to_check:
                        self._log(f"从重定向链中拿到 callback URL")
                        # 验证 state
                        parsed = urllib.parse.urlparse(url_to_check)
                        qs = urllib.parse.parse_qs(parsed.query)
                        returned_state = (qs.get("state", [""])[0] or "").strip()
                        if returned_state != state:
                            self._log("state 不匹配，跳过", "warning")
                            continue
                        # 保存新的 OAuth 参数供后续 token 交换使用
                        self.oauth_start = OAuthStart(
                            auth_url=auth_url,
                            state=state,
                            code_verifier=code_verifier,
                            redirect_uri=OAUTH_REDIRECT_URI,
                        )
                        self._callback_url_from_consent = url_to_check
                        return True

                if response.status_code not in (301, 302, 303, 307, 308):
                    self._log(f"重定向链停在 {response.status_code}: {current_url[:100]}...")
                    # 可能停在 consent 页面，尝试读取 cookie 中的 workspace
                    break

                if not location:
                    break

                if location.startswith("/"):
                    parsed_cur = urllib.parse.urlparse(current_url)
                    location = f"{parsed_cur.scheme}://{parsed_cur.netloc}{location}"

                current_url = location

            # 如果重定向链没有直接给出 code，尝试 workspace 方式
            self._log("重定向链未直接返回 code，尝试从 cookie 读取 workspace...")
            # 更新 oauth_start 为新的参数
            self.oauth_start = OAuthStart(
                auth_url=auth_url,
                state=state,
                code_verifier=code_verifier,
                redirect_uri=OAUTH_REDIRECT_URI,
            )
            return False

        except Exception as e:
            self._log(f"OAuth 重新授权失败: {e}", "error")
            return False

    def _reauthorize_authenticated_session(self) -> Optional[Dict[str, Any]]:
        """利用当前已认证 session 重新发起 OAuth 授权，避免再次走完整登录链路。"""
        self._browser_pause()
        self._log("[Consent Reauth] 尝试基于已认证会话重新发起 OAuth 授权...")

        visited = self._visit_consent_page()
        callback_url = str(getattr(self, "_callback_url_from_consent", "") or "").strip()
        if visited and callback_url:
            self._log("[Consent Reauth] 已从重定向链直接拿到 callback URL")
            return self._handle_oauth_callback(callback_url)

        consent_url = str(
            self._last_oauth_follow_url
            or "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
        ).strip()
        session_data = self._load_workspace_session_data(consent_url)
        if not session_data:
            self._log("[Consent Reauth] 无法获取 consent session 数据", "warning")
            return None

        workspaces = session_data.get("workspaces") or []
        if not workspaces:
            self._log(f"[Consent Reauth] consent session 无 workspaces, keys={list(session_data.keys())}", "warning")
            return None

        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            self._log("[Consent Reauth] workspace_id 为空", "warning")
            return None

        self._log(f"[Consent Reauth] Workspace ID: {workspace_id}")
        continue_url = self._select_workspace(workspace_id)
        if not continue_url:
            return None

        callback_url = self._follow_redirects(continue_url)
        if not callback_url:
            return None

        return self._handle_oauth_callback(callback_url)

    # ========================================================================
    # OAuth 登录流程（注册完成后获取 Token）
    # ========================================================================

    _OAUTH_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    def _decode_session_cookie(self) -> Optional[Dict[str, Any]]:
        """解码 oai-client-auth-session cookie"""
        jar = getattr(self.session.cookies, "jar", None)
        cookie_items = list(jar) if jar is not None else []

        for c in cookie_items:
            name = getattr(c, "name", "") or ""
            if "oai-client-auth-session" not in name:
                continue
            raw_val = (getattr(c, "value", "") or "").strip()
            if not raw_val:
                continue
            candidates = [raw_val]
            try:
                decoded = urllib.parse.unquote(raw_val)
                if decoded != raw_val:
                    candidates.append(decoded)
            except Exception:
                pass
            for val in candidates:
                try:
                    if (val.startswith('"') and val.endswith('"')) or \
                       (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    part = val.split(".")[0] if "." in val else val
                    pad = 4 - len(part) % 4
                    if pad != 4:
                        part += "=" * pad
                    raw = base64.urlsafe_b64decode(part)
                    data = json.loads(raw.decode("utf-8"))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    continue
        return None

    def _oauth_follow_for_code(self, start_url: str, referer: str = None, max_hops: int = 16) -> Optional[str]:
        """手动跟随重定向链提取 authorization code"""
        AUTH_ISSUER = "https://auth.openai.com"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self._OAUTH_UA,
        }
        if referer:
            headers["Referer"] = referer
        current_url = start_url
        self._last_oauth_follow_url = start_url
        for hop in range(max_hops):
            try:
                resp = self.session.get(current_url, headers=headers,
                                        allow_redirects=False, timeout=30)
            except Exception as e:
                # curl_cffi throws on localhost redirect
                maybe_localhost = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if maybe_localhost:
                    self._last_oauth_follow_url = maybe_localhost.group(1)
                    code = _extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        return code
                return None
            final_url = str(resp.url)
            self._last_oauth_follow_url = final_url or current_url
            code = _extract_code_from_url(final_url)
            if code:
                return code
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if not loc:
                    return None
                if loc.startswith("/"):
                    loc = f"{AUTH_ISSUER}{loc}"
                self._last_oauth_follow_url = loc
                code = _extract_code_from_url(loc)
                if code:
                    return code
                current_url = loc
                headers["Referer"] = final_url
                continue
            return None
        return None

    def _fetch_consent_page_html(self, consent_url: str) -> str:
        """获取 consent 页 HTML，用于解析其中的 workspace session 数据。"""
        AUTH_ISSUER = "https://auth.openai.com"
        target_url = consent_url or f"{AUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
        if target_url.startswith("/"):
            target_url = f"{AUTH_ISSUER}{target_url}"

        try:
            response = self.session.get(
                target_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": f"{AUTH_ISSUER}/email-verification",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": self._OAUTH_UA,
                },
                allow_redirects=True,
                timeout=30,
            )
        except Exception:
            return ""

        self._last_oauth_follow_url = str(response.url) or target_url
        content_type = (response.headers.get("content-type", "") or "").lower()
        if response.status_code == 200 and "text/html" in content_type:
            return response.text
        return ""

    def _extract_session_data_from_consent_html(self, html: str) -> Optional[Dict[str, Any]]:
        """从 consent HTML 的 React Router stream 中提取 workspace/session 数据。"""
        if not html or "workspaces" not in html:
            return None

        def _first_match(patterns, text):
            for pattern in patterns:
                matched = re.search(pattern, text, re.S)
                if matched:
                    return matched.group(1)
            return ""

        def _build_from_text(text: str) -> Optional[Dict[str, Any]]:
            if not text or "workspaces" not in text:
                return None

            normalized = text.replace('\\"', '"')
            session_id = _first_match(
                [
                    r'"session_id","([^"]+)"',
                    r'"session_id":"([^"]+)"',
                ],
                normalized,
            )
            client_id = _first_match(
                [
                    r'"openai_client_id","([^"]+)"',
                    r'"openai_client_id":"([^"]+)"',
                ],
                normalized,
            )

            start = normalized.find('"workspaces"')
            if start < 0:
                start = normalized.find("workspaces")
            if start < 0:
                return None

            end = normalized.find('"openai_client_id"', start)
            if end < 0:
                end = normalized.find("openai_client_id", start)
            if end < 0:
                end = min(len(normalized), start + 4000)
            else:
                end = min(len(normalized), end + 600)

            workspace_chunk = normalized[start:end]
            ids = re.findall(r'"id"(?:,|:)"([0-9a-fA-F-]{36})"', workspace_chunk)
            if not ids:
                return None

            kinds = re.findall(r'"kind"(?:,|:)"([^"]+)"', workspace_chunk)
            workspaces = []
            seen = set()
            for idx, workspace_id in enumerate(ids):
                if workspace_id in seen:
                    continue
                seen.add(workspace_id)
                item = {"id": workspace_id}
                if idx < len(kinds):
                    item["kind"] = kinds[idx]
                workspaces.append(item)

            if not workspaces:
                return None

            return {
                "session_id": session_id,
                "openai_client_id": client_id,
                "workspaces": workspaces,
            }

        candidates = [html]

        for quoted in re.findall(
            r'streamController\.enqueue\(("(?:\\.|[^"\\])*")\)',
            html,
            re.S,
        ):
            try:
                decoded = json.loads(quoted)
            except Exception:
                continue
            if decoded:
                candidates.append(decoded)

        if '\\"' in html:
            candidates.append(html.replace('\\"', '"'))

        for candidate in candidates:
            parsed = _build_from_text(candidate)
            if parsed and parsed.get("workspaces"):
                return parsed

        return None

    def _load_workspace_session_data(self, consent_url: str) -> Optional[Dict[str, Any]]:
        """优先从 cookie 解码 session，失败时回退到 consent HTML。"""
        session_data = self._decode_session_cookie()
        if session_data and session_data.get("workspaces"):
            return session_data

        html = self._fetch_consent_page_html(consent_url)
        if not html:
            return session_data

        parsed = self._extract_session_data_from_consent_html(html)
        if parsed and parsed.get("workspaces"):
            if session_data:
                merged = dict(session_data)
                merged.update(parsed)
            else:
                merged = parsed
            self._log(f"[OAuth Login] 从 consent HTML 提取到 {len(merged.get('workspaces', []))} 个 workspace")
            return merged

        return session_data

    def _oauth_submit_workspace_and_org(self, consent_url: str, did: str) -> Optional[str]:
        """选择 workspace 和 org，提取 authorization code"""
        AUTH_ISSUER = "https://auth.openai.com"

        session_data = self._load_workspace_session_data(consent_url)
        if not session_data:
            self._log("[OAuth Login] 无法解码 session cookie", "warning")
            return None

        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            self._log(f"[OAuth Login] session cookie 无 workspaces, keys={list(session_data.keys())}", "warning")
            return None

        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            return None

        self._log(f"[OAuth Login] Workspace ID: {workspace_id}")

        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": AUTH_ISSUER,
            "Referer": consent_url,
            "User-Agent": self._OAUTH_UA,
            "oai-device-id": did,
        }
        h.update(_make_trace_headers())

        # Select workspace
        try:
            resp = self.session.post(
                f"{AUTH_ISSUER}/api/accounts/workspace/select",
                json={"workspace_id": workspace_id},
                headers=h, allow_redirects=False, timeout=30,
            )
        except Exception as e:
            self._log(f"[OAuth Login] workspace/select 异常: {e}", "warning")
            return None

        self._log(f"[OAuth Login] workspace/select -> {resp.status_code}")

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if loc.startswith("/"):
                loc = f"{AUTH_ISSUER}{loc}"
            code = _extract_code_from_url(loc)
            if code:
                return code
            return self._oauth_follow_for_code(loc, referer=consent_url)

        if resp.status_code != 200:
            return None

        try:
            ws_data = resp.json()
        except Exception:
            return None

        ws_next = ws_data.get("continue_url", "")
        orgs = ws_data.get("data", {}).get("orgs", [])

        # Select org if available
        org_id = None
        project_id = None
        if orgs:
            org_id = (orgs[0] or {}).get("id")
            projects = (orgs[0] or {}).get("projects", [])
            if projects:
                project_id = (projects[0] or {}).get("id")

        if org_id:
            org_body = {"org_id": org_id}
            if project_id:
                org_body["project_id"] = project_id
            h_org = dict(h)
            if ws_next:
                h_org["Referer"] = ws_next if ws_next.startswith("http") else f"{AUTH_ISSUER}{ws_next}"

            try:
                resp_org = self.session.post(
                    f"{AUTH_ISSUER}/api/accounts/organization/select",
                    json=org_body, headers=h_org,
                    allow_redirects=False, timeout=30,
                )
            except Exception as e:
                self._log(f"[OAuth Login] organization/select 异常: {e}", "warning")
            else:
                self._log(f"[OAuth Login] organization/select -> {resp_org.status_code}")
                if resp_org.status_code in (301, 302, 303, 307, 308):
                    loc = resp_org.headers.get("Location", "")
                    if loc.startswith("/"):
                        loc = f"{AUTH_ISSUER}{loc}"
                    code = _extract_code_from_url(loc)
                    if code:
                        return code
                    return self._oauth_follow_for_code(loc, referer=h_org.get("Referer"))
                if resp_org.status_code == 200:
                    try:
                        org_data = resp_org.json()
                        org_next = org_data.get("continue_url", "")
                        if org_next:
                            if org_next.startswith("/"):
                                org_next = f"{AUTH_ISSUER}{org_next}"
                            return self._oauth_follow_for_code(org_next, referer=h_org.get("Referer"))
                    except Exception:
                        pass

        if ws_next:
            if ws_next.startswith("/"):
                ws_next = f"{AUTH_ISSUER}{ws_next}"
            return self._oauth_follow_for_code(ws_next, referer=consent_url)

        return None

    def _perform_oauth_login(self, replace_session: bool = False, preferred_workspace_id: str = "") -> Optional[Dict[str, Any]]:
        """注册完成后执行 V2 OAuth 登录状态机，获取授权 token。"""
        oauth_session = cffi_requests.Session(impersonate="chrome131")
        self._log("[OAuth Login] 创建独立 ChatGPT 登录会话，避免复用注册态触发异常")

        if self.proxy_url:
            oauth_session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        oauth_session.headers.update({
            "User-Agent": self._OAUTH_UA,
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })

        settings = get_settings()
        runner = OAuthLoginV2(
            session=oauth_session,
            email=self.email or "",
            password=self.password or "",
            email_service=self.email_service,
            email_info=self.email_info or {},
            device_id=str(self._device_id or oauth_session.cookies.get("oai-did") or uuid.uuid4()),
            config=OAuthLoginConfig(
                oauth_issuer=settings.openai_auth_url.rsplit("/oauth/authorize", 1)[0]
                if settings.openai_auth_url.endswith("/oauth/authorize")
                else "https://auth.openai.com",
                oauth_client_id=settings.openai_client_id,
                oauth_redirect_uri=settings.openai_redirect_uri,
                oauth_scope=settings.openai_scope,
                user_agent=self._OAUTH_UA,
                sec_ch_ua='"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                browser_mode=self.browser_mode,
                impersonate="chrome131",
            ),
            logger=lambda message: self._log(f"[OAuth Login] {message}"),
            sentinel_builder=_build_sentinel_token,
            preferred_workspace_id=preferred_workspace_id,
            excluded_otp_codes=set(self._used_verification_codes),
            first_name=self._profile_first_name,
            last_name=self._profile_last_name,
            birthdate=self._profile_birthdate,
        )
        token_data = runner.run()
        if token_data and token_data.get("access_token"):
            if replace_session and oauth_session is not self.session:
                self.session = oauth_session
            self._log("[OAuth Login] Token 获取成功!")
            return token_data
        self._log("[OAuth Login] 未获取到 ChatGPT Session Token", "error")
        return None

    def _extract_account_from_id_token(self, id_token: str) -> Dict[str, str]:
        """从 id_token 解析邮箱和 account_id"""
        try:
            parts = id_token.split(".")
            if len(parts) < 2:
                return {}
            payload = parts[1]
            pad = 4 - len(payload) % 4
            if pad != 4:
                payload += "=" * pad
            claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
            auth_claims = claims.get("https://api.openai.com/auth") or {}
            return {
                "email": str(claims.get("email") or "").strip(),
                "account_id": str(auth_claims.get("chatgpt_account_id") or "").strip(),
            }
        except Exception:
            return {}

    def _get_workspace_id(self) -> Optional[str]:
        """获取 Workspace ID（对齐当前项目的健壮 cookie 解析逻辑）"""
        import base64
        import json as json_module
        from urllib.parse import unquote

        # 遍历 cookie jar，模糊匹配 oai-client-auth-session
        jar = getattr(self.session.cookies, "jar", None)
        cookie_items = list(jar) if jar is not None else []

        if not cookie_items:
            # 降级：直接 get
            raw = self.session.cookies.get("oai-client-auth-session")
            if raw:
                cookie_items = [type("C", (), {"name": "oai-client-auth-session", "value": raw})()]

        for c in cookie_items:
            name = getattr(c, "name", "") or ""
            if "oai-client-auth-session" not in name:
                continue

            raw_val = (getattr(c, "value", "") or "").strip()
            if not raw_val:
                continue

            self._log(f"找到授权 Cookie: {name} (长度={len(raw_val)})")

            # 尝试原始值和 URL 解码后的值
            candidates = [raw_val]
            try:
                decoded_val = unquote(raw_val)
                if decoded_val != raw_val:
                    candidates.append(decoded_val)
            except Exception:
                pass

            for val in candidates:
                try:
                    # 去除首尾引号
                    if (val.startswith('"') and val.endswith('"')) or \
                       (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]

                    # 取第一段 (JWT payload)
                    part = val.split(".")[0] if "." in val else val
                    pad = 4 - len(part) % 4
                    if pad != 4:
                        part += "=" * pad

                    raw_bytes = base64.urlsafe_b64decode(part)
                    data = json_module.loads(raw_bytes.decode("utf-8"))

                    if not isinstance(data, dict):
                        continue

                    workspaces = data.get("workspaces") or []
                    if not workspaces:
                        self._log(f"Cookie 已解码但无 workspaces，keys={list(data.keys())}", "warning")
                        continue

                    workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
                    if not workspace_id:
                        self._log("无法解析 workspace_id", "error")
                        return None

                    self._log(f"Workspace ID: {workspace_id}")
                    return workspace_id

                except Exception:
                    continue

        self._log("未找到包含 workspace 信息的授权 Cookie", "error")
        return None

    def _select_workspace(self, workspace_id: str) -> Optional[str]:
        """选择 Workspace"""
        try:
            select_body = f'{{"workspace_id":"{workspace_id}"}}'

            response = self.session.post(
                OPENAI_API_ENDPOINTS["select_workspace"],
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                },
                data=select_body,
            )

            if response.status_code != 200:
                self._log(f"选择 workspace 失败: {response.status_code}", "error")
                self._log(f"响应: {response.text[:200]}", "warning")
                return None

            continue_url = str((response.json() or {}).get("continue_url") or "").strip()
            if not continue_url:
                self._log("workspace/select 响应里缺少 continue_url", "error")
                return None

            self._log(f"Continue URL: {continue_url[:100]}...")
            return continue_url

        except Exception as e:
            self._log(f"选择 Workspace 失败: {e}", "error")
            return None

    def _follow_redirects(self, start_url: str) -> Optional[str]:
        """跟随重定向链，寻找回调 URL"""
        try:
            current_url = start_url
            max_redirects = 6

            for i in range(max_redirects):
                self._log(f"重定向 {i+1}/{max_redirects}: {current_url[:100]}...")

                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=15
                )

                location = response.headers.get("Location") or ""

                # 如果不是重定向状态码，停止
                if response.status_code not in [301, 302, 303, 307, 308]:
                    self._log(f"非重定向状态码: {response.status_code}")
                    break

                if not location:
                    self._log("重定向响应缺少 Location 头")
                    break

                # 构建下一个 URL
                import urllib.parse
                next_url = urllib.parse.urljoin(current_url, location)

                # 检查是否包含回调参数
                if "code=" in next_url and "state=" in next_url:
                    self._log(f"找到回调 URL: {next_url[:100]}...")
                    return next_url

                current_url = next_url

            self._log("未能在重定向链中找到回调 URL", "error")
            return None

        except Exception as e:
            self._log(f"跟随重定向失败: {e}", "error")
            return None

    def _get_cookie_value(self, name: str, domain_hint: Optional[str] = None) -> str:
        """从当前会话中读取 Cookie。"""
        jar = getattr(self.session.cookies, "jar", None)
        if jar is None:
            try:
                return self.session.cookies.get(name) or ""
            except Exception:
                return ""

        for cookie in list(jar):
            if getattr(cookie, "name", "") != name:
                continue
            if domain_hint and domain_hint not in (getattr(cookie, "domain", "") or ""):
                continue
            return (getattr(cookie, "value", "") or "").strip()
        return ""

    def _decode_jwt_payload(self, token: str) -> Dict[str, Any]:
        """解析 JWT payload，用于从 access_token 中提取账户信息。"""
        try:
            parts = (token or "").split(".")
            if len(parts) != 3:
                return {}
            payload = parts[1]
            pad = 4 - len(payload) % 4
            if pad != 4:
                payload += "=" * pad
            return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        except Exception:
            return {}

    def _follow_post_auth_continue_url(self) -> bool:
        """跟随注册完成后的 continue_url，确保 ChatGPT 会话真正落地。"""
        self._browser_pause()
        candidates = []
        if self._post_auth_continue_url:
            candidates.append((self._post_auth_continue_url, "https://auth.openai.com/about-you"))
        if self._otp_continue_url and self._otp_continue_url != self._post_auth_continue_url:
            candidates.append((self._otp_continue_url, "https://auth.openai.com/email-verification"))

        if not candidates:
            self._log("[Session Reuse] 无可跟随的 continue_url，直接检查现有会话", "warning")
            return False

        for target_url, referer in candidates:
            url = target_url
            if url.startswith("/"):
                url = urllib.parse.urljoin("https://auth.openai.com", url)
            try:
                response = self.session.get(
                    url,
                    headers={
                        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "upgrade-insecure-requests": "1",
                        "referer": referer,
                        "user-agent": self._OAUTH_UA,
                    },
                    allow_redirects=True,
                    timeout=30,
                )
                self._log(f"[Session Reuse] continue_url 落地完成: {str(response.url)[:120]}...")
                return True
            except Exception as e:
                self._log(f"[Session Reuse] 跟随 continue_url 失败: {e}", "warning")

        return False

    def _reuse_session_and_get_tokens(self) -> Optional[Dict[str, Any]]:
        """移植 0330 的后置认证方案：复用注册会话直接读取 ChatGPT Session。"""
        self._browser_pause()
        try:
            flow_state = self._post_auth_flow_state or self._otp_flow_state
            if not flow_state:
                fallback_url = str(self._post_auth_continue_url or self._otp_continue_url or "").strip()
                if fallback_url:
                    flow_state = extract_flow_state(
                        current_url=fallback_url,
                        auth_base="https://auth.openai.com",
                    )

            reuse_client = SessionReuseClient(
                self.session,
                device_id=self._device_id or "",
                browser_mode=self.browser_mode,
                user_agent=self._OAUTH_UA,
                sec_ch_ua='"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                chrome_full_version="131.0.0.0",
                accept_language="en-US,en;q=0.9",
                logger=lambda message: self._log(f"[Session Reuse] {message}"),
            )

            ok, token_data = reuse_client.reuse_session_and_get_tokens(flow_state)
            if not ok:
                self._log(f"[Session Reuse] {token_data}", "warning")
                return None

            if token_data.get("session_token"):
                self.session_token = token_data["session_token"]
            if not token_data.get("workspace_id"):
                token_data["workspace_id"] = token_data.get("account_id") or ""
            if not token_data.get("email"):
                token_data["email"] = self.email or ""
            return token_data
        except Exception as e:
            self._log(f"[Session Reuse] 提取 Token 异常: {e}", "warning")
            return None

    def _handle_oauth_callback(self, callback_url: str) -> Optional[Dict[str, Any]]:
        """处理 OAuth 回调"""
        try:
            if not self.oauth_start:
                self._log("OAuth 流程未初始化", "error")
                return None

            self._log("处理 OAuth 回调...")
            token_info = self.oauth_manager.handle_callback(
                callback_url=callback_url,
                expected_state=self.oauth_start.state,
                code_verifier=self.oauth_start.code_verifier
            )

            self._log("OAuth 授权成功")
            return token_info

        except Exception as e:
            self._log(f"处理 OAuth 回调失败: {e}", "error")
            return None

    def _normalize_direct_oauth_token_data(self, oauth_token_data: Dict[str, Any]) -> Dict[str, Any]:
        """将直连完整 OAuth 返回值整理为统一 token 结构。"""
        token_data = dict(oauth_token_data or {})
        if not token_data.get("session_token"):
            token_data["session_token"] = self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")
        if not token_data.get("workspace_id"):
            token_data["workspace_id"] = token_data.get("account_id") or ""
        if not token_data.get("email"):
            token_data["email"] = self.email or ""
        return token_data

    def _merge_token_data(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """将 overlay 中的非空 token 字段合并到 base。"""
        merged = dict(base or {})
        for key in (
            "refresh_token",
            "id_token",
            "access_token",
            "session_token",
            "account_id",
            "workspace_id",
            "email",
            "user_id",
            "token_type",
            "expires_in",
        ):
            value = (overlay or {}).get(key)
            if value:
                merged[key] = value
        return merged

    def _run_chatgpt_register_v2(self) -> Optional[Dict[str, Any]]:
        """移植 0330 的注册状态机，直接完成注册并复用会话提取 Token。"""
        try:
            self.password = self._generate_password()
            user_info = generate_random_user_info()
            first_name, _, last_name = user_info["name"].partition(" ")
            last_name = last_name or "Smith"
            self._profile_first_name = first_name
            self._profile_last_name = last_name
            self._profile_birthdate = user_info["birthdate"]

            self._log("3. 使用 0330 注册状态机执行完整注册...")
            self._log(f"执行密码: {self.password}")
            self._log(f"注册信息: {user_info['name']}, 生日: {user_info['birthdate']}")

            client = ChatGPTRegisterClientV2(
                proxy=self.proxy_url,
                verbose=False,
                browser_mode=self.browser_mode,
            )
            client._log = self._log

            email_adapter = _EmailServiceV2Adapter(
                email_service=self.email_service,
                email=self.email or "",
                email_info=self.email_info,
                log_fn=self._log,
                used_codes=self._used_verification_codes,
            )

            success, message = client.register_complete_flow(
                self.email or "",
                self.password,
                first_name,
                last_name,
                user_info["birthdate"],
                email_adapter,
            )
            if not success:
                self._log(f"V2 注册状态机失败: {message}", "warning")
                return None

            self.session = client.session
            self._device_id = client.device_id
            self._post_auth_flow_state = client.last_registration_state
            self._is_existing_account = bool(getattr(client, "is_existing_account", False))
            self.email = self.email or ""

            if not self._is_existing_account:
                self._log("13. 新注册完成，直接执行完整 OAuth 流程（会重新验证邮箱）...")
                direct_oauth_token_data = self._perform_oauth_login(
                    replace_session=False,
                    preferred_workspace_id="",
                )
                if direct_oauth_token_data and (
                    direct_oauth_token_data.get("refresh_token") or direct_oauth_token_data.get("id_token")
                ):
                    token_data = self._normalize_direct_oauth_token_data(direct_oauth_token_data)
                    self.email = token_data.get("email") or self.email
                    self.session_token = token_data.get("session_token") or self.session_token
                    self._log("13.0 完整 OAuth 成功")
                    self._log(f"13.0 完整 OAuth Token 快照: {_format_token_snapshot(token_data)}")
                    return token_data
                self._log("13.0 完整 OAuth 未拿到 refresh_token/id_token，回退到会话复用链路", "warning")

            self._log("13.1 优先复用注册会话获取 Token...")
            session_ok, token_data = client.reuse_session_and_get_tokens()
            if not session_ok:
                self._log(f"V2 会话复用失败: {token_data}", "warning")
                return None

            self.email = token_data.get("email") or self.email
            self.session_token = token_data.get("session_token") or self.session_token
            self._log(f"13.1 会话复用 Token 快照: {_format_token_snapshot(token_data)}")

            if self._is_existing_account:
                self._log("13.2 执行第二阶段 ChatGPT Web 登录获取 Token...")
                oauth_token_data = self._perform_oauth_login(
                    replace_session=False,
                    preferred_workspace_id=token_data.get("workspace_id") or token_data.get("account_id") or "",
                )
                if oauth_token_data and oauth_token_data.get("access_token"):
                    self._log("13.2 已成功获取第二阶段 ChatGPT Token")
                    self._log(f"13.2 第二阶段 Token 快照: {_format_token_snapshot(oauth_token_data)}")
                    token_data = self._merge_token_data(token_data, oauth_token_data)
                else:
                    self._log("13.2 第二阶段未获取到额外 Token，保留会话复用结果", "warning")
                    if oauth_token_data:
                        self._log(f"13.2 第二阶段返回 Token 快照: {_format_token_snapshot(oauth_token_data)}", "warning")

            if not token_data.get("workspace_id"):
                token_data["workspace_id"] = token_data.get("account_id") or ""
            if not token_data.get("email"):
                token_data["email"] = self.email or ""
            self._log(f"13.3 最终 Token 快照: {_format_token_snapshot(token_data)}")
            return token_data
        except Exception as e:
            self._log(f"V2 注册状态机异常: {e}", "warning")
            return None

    def run(self) -> RegistrationResult:
        """
        执行完整的注册流程

        支持已注册账号自动登录：
        - 如果检测到邮箱已注册，自动切换到登录流程
        - 已注册账号跳过：设置密码、发送验证码、创建用户账户
        - 共用步骤：获取验证码、验证验证码、Workspace 和 OAuth 回调

        Returns:
            RegistrationResult: 注册结果
        """
        result = RegistrationResult(success=False, logs=self.logs)

        try:
            self._log("=" * 60)
            self._log("开始注册流程")
            self._log(f"执行模式: {self.browser_mode}")
            if self.browser_mode != "protocol":
                self._log("说明: 当前仍为协议注册链路，执行模式主要影响请求节奏与兼容头")
            self._log("=" * 60)

            # 1. 检查 IP 地理位置
            self._log("1. 检查 IP 地理位置...")
            ip_ok, location = self._check_ip_location()
            if not ip_ok:
                result.error_message = f"IP 地理位置不支持: {location}"
                self._log(f"IP 检查失败: {location}", "error")
                return result

            self._log(f"IP 位置: {location}")

            # 2. 创建邮箱
            self._log("2. 创建邮箱...")
            if not self._create_email():
                result.error_message = "创建邮箱失败"
                return result

            result.email = self.email

            auth_method = "session_reuse_v2"
            token_data = self._run_chatgpt_register_v2()
            if not token_data:
                result.error_message = "V2 注册状态机失败"
                return result
            if token_data.get("refresh_token"):
                auth_method = "session_reuse_v2+oauth_login_v2"

            # 从 token 数据提取信息
            result.access_token = token_data.get("access_token", "")
            result.refresh_token = token_data.get("refresh_token", "")
            result.id_token = token_data.get("id_token", "")
            result.session_token = token_data.get("session_token", "")
            result.account_id = token_data.get("account_id", "")
            result.workspace_id = token_data.get("workspace_id", "")
            result.password = self.password or ""
            if token_data.get("email"):
                result.email = token_data.get("email", "")

            # 从 id_token 解析 account_id
            if result.id_token:
                account_info = self._extract_account_from_id_token(result.id_token)
                if not result.account_id:
                    result.account_id = account_info.get("account_id", "")
                if account_info.get("email"):
                    result.email = account_info["email"]
            if not result.workspace_id:
                result.workspace_id = result.account_id or ""

            # 设置来源标记
            result.source = "login" if self._is_existing_account else "register"

            # 尝试获取 session_token 从 cookie
            session_cookie = self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")
            if session_cookie and not result.session_token:
                result.session_token = session_cookie
            if result.session_token:
                self.session_token = result.session_token
                self._log(f"获取到 Session Token")

            # 17. 完成
            self._log("=" * 60)
            if self._is_existing_account:
                self._log("登录成功! (已注册账号)")
            else:
                self._log("注册成功!")
            self._log(f"邮箱: {result.email}")
            self._log(f"Account ID: {result.account_id}")
            self._log(f"Workspace ID: {result.workspace_id}")
            self._log("=" * 60)

            result.success = True
            result.metadata = {
                "email_service": self.email_service.service_type.value,
                "browser_mode": self.browser_mode,
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
                "auth_method": auth_method,
                "auth_provider": token_data.get("auth_provider"),
                "user_id": token_data.get("user_id", ""),
            }

            return result

        except Exception as e:
            self._log(f"注册过程中发生未预期错误: {e}", "error")
            result.error_message = str(e)
            return result

    def save_to_database(self, result: RegistrationResult) -> bool:
        """
        保存注册结果到数据库

        Args:
            result: 注册结果

        Returns:
            是否保存成功
        """
        if not result.success:
            return False

        try:
            # 获取默认 client_id
            settings = get_settings()

            with get_db() as db:
                # 保存账户信息
                account = crud.create_account(
                    db,
                    email=result.email,
                    password=result.password,
                    client_id=settings.openai_client_id,
                    session_token=result.session_token,
                    email_service=self.email_service.service_type.value,
                    email_service_id=self.email_info.get("service_id") if self.email_info else None,
                    account_id=result.account_id,
                    workspace_id=result.workspace_id,
                    access_token=result.access_token,
                    refresh_token=result.refresh_token,
                    id_token=result.id_token,
                    proxy_used=self.proxy_url,
                    extra_data=result.metadata,
                    source=result.source
                )

                self._log(f"账户已保存到数据库，ID: {account.id}")
                return True

        except Exception as e:
            self._log(f"保存到数据库失败: {e}", "error")
            return False
