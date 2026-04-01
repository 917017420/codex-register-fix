"""
Web UI 启动入口
"""

import uvicorn
import logging
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
# PyInstaller 打包后 __file__ 在临时解压目录，需要用 sys.executable 所在目录作为数据目录
import os
if getattr(sys, 'frozen', False):
    # 打包后：使用可执行文件所在目录
    project_root = Path(sys.executable).parent
    _src_root = Path(sys._MEIPASS)
else:
    project_root = Path(__file__).parent
    _src_root = project_root
sys.path.insert(0, str(_src_root))

from src.core.utils import setup_logging
from src.database.init_db import initialize_database
from src.config.settings import get_settings


def _load_dotenv():
    """加载 .env 文件（可执行文件同目录或项目根目录）"""
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def setup_application():
    """设置应用程序"""
    # 加载 .env 文件（优先级低于已有环境变量）
    _load_dotenv()

    # 确保数据目录和日志目录在可执行文件所在目录（打包后也适用）
    data_dir = project_root / "data"
    logs_dir = project_root / "logs"
    data_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)

    # 将数据目录路径注入环境变量，供数据库配置使用
    os.environ.setdefault("APP_DATA_DIR", str(data_dir))
    os.environ.setdefault("APP_LOGS_DIR", str(logs_dir))

    # 初始化数据库（必须先于获取设置）
    try:
        initialize_database()
    except Exception as e:
        print(f"数据库初始化失败: {e}")
        raise

    # 获取配置（需要数据库已初始化）
    settings = get_settings()

    # 配置日志（日志文件写到实际 logs 目录）
    log_file = str(logs_dir / Path(settings.log_file).name)
    setup_logging(
        log_level=settings.log_level,
        log_file=log_file
    )

    logger = logging.getLogger(__name__)
    logger.info("数据库初始化完成")
    logger.info(f"数据目录: {data_dir}")
    logger.info(f"日志目录: {logs_dir}")

    logger.info("应用程序设置完成")
    return settings


def start_webui():
    """启动 Web UI"""
    # 设置应用程序
    settings = setup_application()

    # 导入 FastAPI 应用（延迟导入以避免循环依赖）
    from src.web.app import app

    # 配置 uvicorn
    uvicorn_config = {
        "app": "src.web.app:app",
        "host": settings.webui_host,
        "port": settings.webui_port,
        "reload": settings.debug,
        "log_level": "info" if settings.debug else "warning",
        "access_log": settings.debug,
        "ws": "websockets",
    }

    logger = logging.getLogger(__name__)
    logger.info(f"启动 Web UI 在 http://{settings.webui_host}:{settings.webui_port}")
    logger.info(f"调试模式: {settings.debug}")

    # 启动服务器
    uvicorn.run(**uvicorn_config)


def main():
    """主函数"""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="OpenAI/Codex CLI 自动注册系统 Web UI")
    parser.add_argument("--host", help="监听主机 (也可通过 WEBUI_HOST 环境变量设置)")
    parser.add_argument("--port", type=int, help="监听端口 (也可通过 WEBUI_PORT 环境变量设置)")
    parser.add_argument("--debug", action="store_true", help="启用调试模式 (也可通过 DEBUG=1 环境变量设置)")
    parser.add_argument("--reload", action="store_true", help="启用热重载")
    parser.add_argument("--log-level", help="日志级别 (也可通过 LOG_LEVEL 环境变量设置)")
    parser.add_argument("--access-password", help="Web UI 访问密钥 (也可通过 WEBUI_ACCESS_PASSWORD 环境变量设置)")
    args = parser.parse_args()

    # 确保数据库已初始化，再处理命令行配置覆盖，避免读取到默认缓存值。
    _load_dotenv()
    data_dir = project_root / "data"
    logs_dir = project_root / "logs"
    data_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)
    os.environ.setdefault("APP_DATA_DIR", str(data_dir))
    os.environ.setdefault("APP_LOGS_DIR", str(logs_dir))
    initialize_database()

    # 更新配置
    from src.config.settings import update_settings

    updates = {}
    
    # 优先使用命令行参数，如果没有则尝试从环境变量获取
    host = args.host or os.environ.get("WEBUI_HOST")
    if host:
        updates["webui_host"] = host
        
    port = args.port or os.environ.get("WEBUI_PORT")
    if port:
        updates["webui_port"] = int(port)
        
    debug = args.debug or os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    if debug:
        updates["debug"] = debug
        
    log_level = args.log_level or os.environ.get("LOG_LEVEL")
    if log_level:
        updates["log_level"] = log_level
        
    access_password = args.access_password or os.environ.get("WEBUI_ACCESS_PASSWORD")
    if access_password:
        updates["webui_access_password"] = access_password

    if updates:
        update_settings(**updates)

    # 启动 Web UI
    start_webui()


if __name__ == "__main__":
    main()
