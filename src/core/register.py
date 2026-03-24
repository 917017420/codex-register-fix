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
from .http_client import OpenAIHTTPClient, HTTPClientError
from ..services import EmailServiceFactory, BaseEmailService, EmailServiceType
from ..database import crud
from ..database.session import get_db
from ..config.constants import (
    OPENAI_API_ENDPOINTS,
    OPENAI_PAGE_TYPES,
    generate_random_user_info,
    OTP_CODE_PATTERN,
    DEFAULT_PASSWORD_LENGTH,
    PASSWORD_CHARSET,
    AccountStatus,
    TaskStatus,
)
from ..config.settings import get_settings


logger = logging.getLogger(__name__)


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


class RegistrationEngine:
    """
    注册引擎
    负责协调邮箱服务、OAuth 流程和 OpenAI API 调用
    """

    def __init__(
        self,
        email_service: BaseEmailService,
        proxy_url: Optional[str] = None,
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None
    ):
        """
        初始化注册引擎

        Args:
            email_service: 邮箱服务实例
            proxy_url: 代理 URL
            callback_logger: 日志回调函数
            task_uuid: 任务 UUID（用于数据库记录）
        """
        self.email_service = email_service
        self.proxy_url = proxy_url
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
        self._otp_continue_url: Optional[str] = None  # OTP 验证后的 continue_url
        self._device_id: Optional[str] = None  # Device ID，所有 API 请求共用

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
            )

            if code:
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
                continue_url = (resp_data or {}).get("continue_url") or \
                               (resp_data or {}).get("url") or \
                               (resp_data or {}).get("redirect_url")
                if continue_url:
                    self._otp_continue_url = continue_url
                    self._log(f"验证码响应包含 continue_url: {continue_url[:100]}...")
            except Exception:
                pass

            return True

        except Exception as e:
            self._log(f"验证验证码失败: {e}", "error")
            return False

    def _create_user_account(self) -> bool:
        """创建用户账户"""
        try:
            user_info = generate_random_user_info()
            self._log(f"生成用户信息: {user_info['name']}, 生日: {user_info['birthdate']}")

            headers = {
                "referer": "https://auth.openai.com/about-you",
                "origin": "https://auth.openai.com",
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": self._OAUTH_UA,
                "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            }
            if self._device_id:
                headers["oai-device-id"] = self._device_id
            headers.update(_make_trace_headers())

            response = self.session.post(
                OPENAI_API_ENDPOINTS["create_account"],
                headers=headers,
                json=user_info,
                impersonate="chrome131",
            )

            self._log(f"账户创建状态: {response.status_code}")

            if response.status_code != 200:
                self._log(f"账户创建失败: {response.text[:200]}", "warning")
                return False

            # 解析响应中的 continue_url 并跟随重定向，
            # 以获取包含 workspaces 信息的 oai-client-auth-session cookie
            try:
                resp_data = response.json()
                continue_url = (resp_data or {}).get("continue_url") or \
                               (resp_data or {}).get("url") or \
                               (resp_data or {}).get("redirect_url")
                if continue_url:
                    self._log(f"跟随 create_account continue_url: {continue_url[:100]}...")
                    self.session.get(
                        continue_url,
                        headers={
                            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "upgrade-insecure-requests": "1",
                            "referer": "https://auth.openai.com/about-you",
                        },
                        allow_redirects=True,
                        timeout=30,
                    )
                    self._log("continue_url 跟随完成")
                else:
                    self._log("create_account 响应中未包含 continue_url", "warning")
            except Exception as e:
                self._log(f"跟随 continue_url 失败: {e}", "warning")

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
        for hop in range(max_hops):
            try:
                resp = self.session.get(current_url, headers=headers,
                                        allow_redirects=False, timeout=30)
            except Exception as e:
                # curl_cffi throws on localhost redirect
                maybe_localhost = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                if maybe_localhost:
                    code = _extract_code_from_url(maybe_localhost.group(1))
                    if code:
                        return code
                return None
            final_url = str(resp.url)
            code = _extract_code_from_url(final_url)
            if code:
                return code
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if not loc:
                    return None
                if loc.startswith("/"):
                    loc = f"{AUTH_ISSUER}{loc}"
                code = _extract_code_from_url(loc)
                if code:
                    return code
                current_url = loc
                headers["Referer"] = final_url
                continue
            return None
        return None

    def _oauth_submit_workspace_and_org(self, consent_url: str, did: str) -> Optional[str]:
        """选择 workspace 和 org，提取 authorization code"""
        AUTH_ISSUER = "https://auth.openai.com"

        session_data = self._decode_session_cookie()
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

    def _perform_oauth_login(self) -> Optional[Dict[str, Any]]:
        """
        注册完成后执行完整的 OAuth 登录流程，获取 workspace 和 token。
        等效于当前项目的 perform_codex_oauth_login_http()。

        Returns:
            token 字典（含 access_token, refresh_token, id_token），失败返回 None
        """
        from ..config.constants import (
            OAUTH_AUTH_URL, OAUTH_REDIRECT_URI, OAUTH_SCOPE, OAUTH_CLIENT_ID,
        )
        from .openai.oauth import _pkce_verifier, _sha256_b64url_no_pad

        AUTH_ISSUER = "https://auth.openai.com"
        UA = self._OAUTH_UA

        self._log("[OAuth Login] 开始执行 OAuth 登录流程...")

        # 清除注册流程留下的 auth cookies，避免干扰新的 OAuth 登录
        # 保留 oai-did（device ID）
        cookies_to_remove = []
        jar = getattr(self.session.cookies, "jar", None)
        if jar is not None:
            for c in list(jar):
                name = getattr(c, "name", "") or ""
                if name in ("login_session", "oai-client-auth-session",
                            "__Host-next-auth.csrf-token",
                            "__Secure-next-auth.callback-url",
                            "__Secure-next-auth.session-token"):
                    cookies_to_remove.append(c)
            for c in cookies_to_remove:
                jar.clear(getattr(c, "domain", ""), getattr(c, "path", "/"), c.name)
        self._log(f"[OAuth Login] 清除了 {len(cookies_to_remove)} 个旧 auth cookies")

        # 获取 / 设置 device_id
        did = self.session.cookies.get("oai-did") or str(uuid.uuid4())
        self.session.cookies.set("oai-did", did, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", did, domain="auth.openai.com")

        # 生成新的 PKCE 参数
        code_verifier = _pkce_verifier()
        code_challenge = _sha256_b64url_no_pad(code_verifier)
        state = secrets.token_urlsafe(24)

        authorize_params = {
            "response_type": "code",
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "scope": OAUTH_SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        authorize_url = f"{AUTH_ISSUER}/oauth/authorize?{urllib.parse.urlencode(authorize_params)}"

        def _oauth_json_headers(referer: str):
            h = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": AUTH_ISSUER,
                "Referer": referer,
                "User-Agent": UA,
                "oai-device-id": did,
            }
            h.update(_make_trace_headers())
            return h

        # ---- Step 1: Bootstrap OAuth session ----
        self._log("[OAuth Login] 1/7 GET /oauth/authorize")
        try:
            r = self.session.get(authorize_url, headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://chatgpt.com/",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": UA,
            }, allow_redirects=True, timeout=30)
        except Exception as e:
            self._log(f"[OAuth Login] /oauth/authorize 异常: {e}", "error")
            return None

        authorize_final_url = str(r.url)
        # Check if we got login_session cookie; if not, try oauth2/auth endpoint
        has_login = any(getattr(c, "name", "") == "login_session"
                        for c in self.session.cookies)
        if not has_login:
            oauth2_url = f"{AUTH_ISSUER}/api/oauth/oauth2/auth"
            try:
                r2 = self.session.get(oauth2_url, headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": authorize_url,
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": UA,
                }, params=authorize_params, allow_redirects=True, timeout=30)
                authorize_final_url = str(r2.url)
            except Exception as e:
                self._log(f"[OAuth Login] /api/oauth/oauth2/auth 异常: {e}", "warning")

        continue_referer = (authorize_final_url
                            if authorize_final_url.startswith(AUTH_ISSUER)
                            else f"{AUTH_ISSUER}/log-in")

        # ---- Step 2: POST /api/accounts/authorize/continue ----
        self._log("[OAuth Login] 2/7 POST /api/accounts/authorize/continue")
        sentinel_authorize = _build_sentinel_token(
            self.session, did, flow="authorize_continue", user_agent=UA,
        )
        headers_continue = _oauth_json_headers(continue_referer)
        if sentinel_authorize:
            headers_continue["openai-sentinel-token"] = sentinel_authorize

        try:
            resp_continue = self.session.post(
                f"{AUTH_ISSUER}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": self.email}},
                headers=headers_continue, timeout=30, allow_redirects=False,
            )
        except Exception as e:
            self._log(f"[OAuth Login] authorize/continue 异常: {e}", "error")
            return None

        self._log(f"[OAuth Login] authorize/continue -> {resp_continue.status_code}")

        # Handle invalid_auth_step by re-bootstrapping with aggressive cookie cleanup
        if resp_continue.status_code == 400 and "invalid_auth_step" in (resp_continue.text or ""):
            self._log("[OAuth Login] invalid_auth_step, 清除残留 cookies 并重新 bootstrap...")
            # Aggressively clear ALL auth.openai.com cookies except oai-did
            jar = getattr(self.session.cookies, "jar", None)
            if jar is not None:
                to_remove = []
                for c in list(jar):
                    name = getattr(c, "name", "") or ""
                    if name != "oai-did":
                        to_remove.append(c)
                for c in to_remove:
                    try:
                        jar.clear(getattr(c, "domain", ""), getattr(c, "path", "/"), c.name)
                    except Exception:
                        pass
                self._log(f"[OAuth Login] 重新 bootstrap: 清除了 {len(to_remove)} 个 cookies")
            # Re-set oai-did
            self.session.cookies.set("oai-did", did, domain=".auth.openai.com")
            self.session.cookies.set("oai-did", did, domain="auth.openai.com")

            try:
                r = self.session.get(authorize_url, headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://chatgpt.com/",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": UA,
                }, allow_redirects=True, timeout=30)
                authorize_final_url = str(r.url)
            except Exception as e:
                self._log(f"[OAuth Login] bootstrap 重试异常: {e}", "error")
                return None
            # oauth2/auth fallback if login_session is still missing
            has_login = any(getattr(c, "name", "") == "login_session"
                           for c in self.session.cookies)
            if not has_login:
                try:
                    r2 = self.session.get(f"{AUTH_ISSUER}/api/oauth/oauth2/auth", headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": authorize_url,
                        "Upgrade-Insecure-Requests": "1",
                        "User-Agent": UA,
                    }, params=authorize_params, allow_redirects=True, timeout=30)
                    authorize_final_url = str(r2.url)
                except Exception:
                    pass
            continue_referer = (authorize_final_url
                                if authorize_final_url.startswith(AUTH_ISSUER)
                                else f"{AUTH_ISSUER}/log-in")
            sentinel_authorize = _build_sentinel_token(
                self.session, did, flow="authorize_continue", user_agent=UA,
            )
            headers_continue = _oauth_json_headers(continue_referer)
            if sentinel_authorize:
                headers_continue["openai-sentinel-token"] = sentinel_authorize
            try:
                resp_continue = self.session.post(
                    f"{AUTH_ISSUER}/api/accounts/authorize/continue",
                    json={"username": {"kind": "email", "value": self.email}},
                    headers=headers_continue, timeout=30, allow_redirects=False,
                )
            except Exception as e:
                self._log(f"[OAuth Login] authorize/continue 重试异常: {e}", "error")
                return None

        if resp_continue.status_code != 200:
            self._log(
                f"[OAuth Login] authorize/continue 非200: {resp_continue.status_code}, "
                f"body={resp_continue.text[:220]}",
                "error",
            )
            return None

        try:
            continue_data = resp_continue.json()
        except Exception:
            self._log("[OAuth Login] authorize/continue JSON 解析失败", "error")
            return None

        continue_url = continue_data.get("continue_url", "")
        page_type = (continue_data.get("page") or {}).get("type", "")

        # ---- Step 3: POST /api/accounts/password/verify ----
        self._log("[OAuth Login] 3/7 POST /api/accounts/password/verify")
        sentinel_pwd = _build_sentinel_token(
            self.session, did, flow="password_verify", user_agent=UA,
        )
        headers_verify = _oauth_json_headers(f"{AUTH_ISSUER}/log-in/password")
        if sentinel_pwd:
            headers_verify["openai-sentinel-token"] = sentinel_pwd

        try:
            resp_verify = self.session.post(
                f"{AUTH_ISSUER}/api/accounts/password/verify",
                json={"password": self.password},
                headers=headers_verify, timeout=30, allow_redirects=False,
            )
        except Exception as e:
            self._log(f"[OAuth Login] password/verify 异常: {e}", "error")
            return None

        self._log(f"[OAuth Login] password/verify -> {resp_verify.status_code}")

        if resp_verify.status_code != 200:
            self._log(
                f"[OAuth Login] password/verify 非200: {resp_verify.status_code}, "
                f"body={resp_verify.text[:220]}",
                "error",
            )
            return None

        try:
            verify_data = resp_verify.json()
        except Exception:
            self._log("[OAuth Login] password/verify JSON 解析失败", "error")
            return None

        continue_url = verify_data.get("continue_url", "") or continue_url
        page_type = (verify_data.get("page") or {}).get("type", "") or page_type

        # ---- Step 4: Handle OTP if needed ----
        need_oauth_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in (continue_url or "")
            or "email-otp" in (continue_url or "")
        )

        if need_oauth_otp:
            self._log("[OAuth Login] 4/7 检测到邮箱 OTP 验证")
            headers_otp = _oauth_json_headers(f"{AUTH_ISSUER}/email-verification")
            tried_codes: set = set()
            otp_success = False
            otp_deadline = time.time() + 120
            # Record current time so email service filters out old (registration) OTP
            oauth_otp_sent_at = time.time()

            while time.time() < otp_deadline and not otp_success:
                email_id = self.email_info.get("service_id") if self.email_info else None
                try:
                    code = self.email_service.get_verification_code(
                        email=self.email,
                        email_id=email_id,
                        timeout=5,
                        pattern=OTP_CODE_PATTERN,
                        otp_sent_at=oauth_otp_sent_at,
                    )
                except Exception:
                    code = None

                if code and code not in tried_codes:
                    tried_codes.add(code)
                    self._log(f"[OAuth Login] 尝试 OTP: {code}")
                    try:
                        resp_otp = self.session.post(
                            f"{AUTH_ISSUER}/api/accounts/email-otp/validate",
                            json={"code": code}, headers=headers_otp,
                            timeout=30, allow_redirects=False,
                        )
                    except Exception as e:
                        self._log(f"[OAuth Login] email-otp/validate 异常: {e}", "warning")
                        continue

                    if resp_otp.status_code == 200:
                        try:
                            otp_data = resp_otp.json()
                            continue_url = otp_data.get("continue_url", "") or continue_url
                            page_type = (otp_data.get("page") or {}).get("type", "") or page_type
                            otp_success = True
                        except Exception:
                            pass
                    else:
                        self._log(f"[OAuth Login] OTP 验证返回 {resp_otp.status_code}", "warning")
                else:
                    elapsed = int(120 - max(0, otp_deadline - time.time()))
                    self._log(f"[OAuth Login] OTP 等待中... ({elapsed}s/120s)")
                    time.sleep(3)

            if not otp_success:
                self._log("[OAuth Login] OAuth 阶段 OTP 验证失败", "error")
                return None

        # ---- Step 5-6: Follow consent/workspace/callback chain ----
        code = None
        consent_url = continue_url
        if consent_url and consent_url.startswith("/"):
            consent_url = f"{AUTH_ISSUER}{consent_url}"
        if not consent_url and "consent" in page_type:
            consent_url = f"{AUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
        if consent_url:
            code = _extract_code_from_url(consent_url)

        if not code and consent_url:
            self._log("[OAuth Login] 5/7 跟随 continue_url 提取 code")
            code = self._oauth_follow_for_code(consent_url, referer=f"{AUTH_ISSUER}/log-in/password")

        consent_hint = (
            ("consent" in (consent_url or ""))
            or ("sign-in-with-chatgpt" in (consent_url or ""))
            or ("workspace" in (consent_url or ""))
            or ("organization" in (consent_url or ""))
            or ("consent" in page_type)
            or ("organization" in page_type)
        )

        if not code and consent_hint:
            if not consent_url:
                consent_url = f"{AUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._log("[OAuth Login] 6/7 执行 workspace/org 选择")
            code = self._oauth_submit_workspace_and_org(consent_url, did)

        if not code:
            fallback_consent = f"{AUTH_ISSUER}/sign-in-with-chatgpt/codex/consent"
            self._log("[OAuth Login] 6/7 回退 consent 路径重试")
            code = self._oauth_submit_workspace_and_org(fallback_consent, did)
            if not code:
                code = self._oauth_follow_for_code(
                    fallback_consent, referer=f"{AUTH_ISSUER}/log-in/password",
                )

        if not code:
            self._log("[OAuth Login] 未获取到 authorization code", "error")
            return None

        # ---- Step 7: Exchange code for tokens ----
        self._log("[OAuth Login] 7/7 POST /oauth/token")
        try:
            token_resp = self.session.post(
                f"{AUTH_ISSUER}/oauth/token",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": UA,
                },
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "client_id": OAUTH_CLIENT_ID,
                    "code_verifier": code_verifier,
                },
                timeout=60,
            )
        except Exception as e:
            self._log(f"[OAuth Login] /oauth/token 异常: {e}", "error")
            return None

        self._log(f"[OAuth Login] /oauth/token -> {token_resp.status_code}")

        if token_resp.status_code != 200:
            self._log(
                f"[OAuth Login] token 交换失败: {token_resp.status_code} "
                f"{token_resp.text[:200]}",
                "error",
            )
            return None

        try:
            data = token_resp.json()
        except Exception:
            self._log("[OAuth Login] token 响应解析失败", "error")
            return None

        if not data.get("access_token"):
            self._log("[OAuth Login] token 响应缺少 access_token", "error")
            return None

        self._log("[OAuth Login] Token 获取成功!")
        return data

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

            # 3. 初始化会话
            self._log("3. 初始化会话...")
            if not self._init_session():
                result.error_message = "初始化会话失败"
                return result

            # 4. 开始 OAuth 流程
            self._log("4. 开始 OAuth 授权流程...")
            if not self._start_oauth():
                result.error_message = "开始 OAuth 流程失败"
                return result

            # 5. 获取 Device ID
            self._log("5. 获取 Device ID...")
            did = self._get_device_id()
            if not did:
                result.error_message = "获取 Device ID 失败"
                return result

            # 6. 检查 Sentinel 拦截
            self._log("6. 检查 Sentinel 拦截...")
            sen_token = self._check_sentinel(did)
            if sen_token:
                self._log("Sentinel 检查通过")
            else:
                self._log("Sentinel 检查失败或未启用", "warning")

            # 7. 提交注册表单 + 解析响应判断账号状态
            self._log("7. 提交注册表单...")
            signup_result = self._submit_signup_form(did, sen_token)
            if not signup_result.success:
                result.error_message = f"提交注册表单失败: {signup_result.error_message}"
                return result

            # 8. [已注册账号跳过] 注册密码
            if self._is_existing_account:
                self._log("8. [已注册账号] 跳过密码设置，OTP 已自动发送")
            else:
                self._log("8. 注册密码...")
                password_ok, password = self._register_password()
                if not password_ok:
                    result.error_message = "注册密码失败"
                    return result

            # 9. [已注册账号跳过] 发送验证码
            if self._is_existing_account:
                self._log("9. [已注册账号] 跳过发送验证码，使用自动发送的 OTP")
                # 已注册账号的 OTP 在提交表单时已自动发送，记录时间戳
                self._otp_sent_at = time.time()
            else:
                self._log("9. 发送验证码...")
                if not self._send_verification_code():
                    result.error_message = "发送验证码失败"
                    return result

            # 10. 获取验证码
            self._log("10. 等待验证码...")
            code = self._get_verification_code()
            if not code:
                result.error_message = "获取验证码失败"
                return result

            # 11. 验证验证码
            self._log("11. 验证验证码...")
            if not self._validate_verification_code(code):
                result.error_message = "验证验证码失败"
                return result

            # 12. [已注册账号跳过] 创建用户账户
            if self._is_existing_account:
                self._log("12. [已注册账号] 跳过创建用户账户")
                # 已注册账号：跟随 validate_otp 返回的 continue_url 以刷新 cookie
                otp_continue = getattr(self, "_otp_continue_url", None)
                if otp_continue:
                    self._log(f"12.1 跟随 OTP continue_url 刷新 cookie...")
                    try:
                        self.session.get(
                            otp_continue,
                            headers={
                                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                "upgrade-insecure-requests": "1",
                                "referer": "https://auth.openai.com/email-verification",
                            },
                            allow_redirects=True,
                            timeout=30,
                        )
                        self._log("OTP continue_url 跟随完成")
                    except Exception as e:
                        self._log(f"跟随 OTP continue_url 失败: {e}", "warning")
            else:
                self._log("12. 创建用户账户...")
                if not self._create_user_account():
                    result.error_message = "创建用户账户失败"
                    return result

            # 12.5 执行完整 OAuth 登录流程（获取 Token）
            # 注册/OTP 流程结束后，需要单独走一次完整的 OAuth 登录才能获取 workspace 和 token
            self._log("13. 执行 OAuth 登录获取 Token...")
            token_data = self._perform_oauth_login()
            if not token_data:
                result.error_message = "OAuth 登录失败"
                return result

            # 从 token 数据提取信息
            result.access_token = token_data.get("access_token", "")
            result.refresh_token = token_data.get("refresh_token", "")
            result.id_token = token_data.get("id_token", "")
            result.password = self.password or ""

            # 从 id_token 解析 account_id
            if result.id_token:
                account_info = self._extract_account_from_id_token(result.id_token)
                result.account_id = account_info.get("account_id", "")
                if account_info.get("email"):
                    result.email = account_info["email"]

            # 设置来源标记
            result.source = "login" if self._is_existing_account else "register"

            # 尝试获取 session_token 从 cookie
            session_cookie = self.session.cookies.get("__Secure-next-auth.session-token")
            if session_cookie:
                self.session_token = session_cookie
                result.session_token = session_cookie
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
                "proxy_used": self.proxy_url,
                "registered_at": datetime.now().isoformat(),
                "is_existing_account": self._is_existing_account,
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
