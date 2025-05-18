from typing import Dict, Optional, Any
from requests.sessions import Session
from requests import Request, Response
from hashlib import sha256
import time
import logging
import argparse  # 添加argparse模块用于命令行参数解析
import sys  # 添加sys模块用于访问命令行参数

logging.basicConfig(
    level=logging.ERROR,
    format="[%(asctime)s][%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

host = "http://192.168.0.1"
goform_get_path = "/goform/goform_get_cmd_process"
goform_set_path = "/goform/goform_set_cmd_process"
API_GET_URL = host + goform_get_path
API_SET_URL = host + goform_set_path
password = "admin"
HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Referer": host + "/index.html",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
}

session = Session()


class ServerError(Exception):
    """Exception raised for server errors."""

    pass


"""
cmd_list = [
    "wifi_onoff_state",
    "wifi_lbd_enable",
    "guest_switch",
    "wifi_chip1_ssid2_max_access_num",
    "m_SSID2",
    "wifi_chip2_ssid2_max_access_num",
    "wifi_chip1_ssid1_wifi_coverage",
    "apn_interface_version",
    "m_ssid_enable",
    "imei",
    "network_type",
    "rssi",
    "rscp",
    "lte_rsrp",
    "imsi",
    "sim_imsi",
    "cr_version",
    "wa_version",
    "hardware_version",
    "web_version",
    "wa_inner_version",
    "wifi_chip1_ssid1_max_access_num",
    "iccid",
    "wifi_chip1_ssid1_ssid",
    "wifi_chip1_ssid1_auth_mode",
    "wifi_chip1_ssid1_password_encode",
    "wifi_chip2_ssid1_ssid",
    "wifi_chip2_ssid1_auth_mode",
    "m_HideSSID",
    "wifi_chip2_ssid1_password_encode",
    "wifi_chip2_ssid1_max_access_num",
    "lan_ipaddr",
    "lan_ipaddr",
    "mac_address",
    "msisdn",
    "LocalDomain",
    "wan_ipaddr",
    "static_wan_ipaddr",
    "ipv6_wan_ipaddr",
    "ipv6_pdp_type",
    "ipv6_pdp_type_ui",
    "pdp_type",
    "pdp_type_ui",
    "opms_wan_mode",
    "queryWiFiModuleSwitch",
    "opms_wan_auto_mode",
    "OOM_TEMP_PRO",
    "privacy_read_flag",
    "LD",
    "ppp_status",
    "Z5g_snr",
    "Z5g_rsrp",
    "wan_lte_ca",
    "lte_ca_pcell_band",
    "lte_ca_pcell_bandwidth",
    "lte_ca_scell_band",
    "lte_ca_scell_bandwidth",
    "lte_ca_pcell_arfcn",
    "lte_ca_scell_arfcn",
    "lte_multi_ca_scell_info",
    "queryWiFiModuleSwitch",
    "wan_active_band",
    "wifi_onoff_state",
    "guest_switch",
    "web_wifi_password_init_flag", 
    "wifi_chip1_ssid2_max_access_num",
    "wifi_chip2_ssid2_max_access_num",
    "wifi_chip1_ssid1_wifi_coverage",
    "wifi_chip1_ssid1_max_access_num",
    "wifi_chip1_ssid1_ssid",
    "wifi_chip1_ssid1_auth_mode",
    "wifi_chip1_ssid1_password_encode",
    "wifi_chip2_ssid1_ssid",
    "wifi_chip2_ssid1_auth_mode",
    "wifi_chip2_ssid1_password_encode",
    "wifi_chip2_ssid1_max_access_num",
    "wifi_chip1_ssid2_ssid",
    "wifi_chip2_ssid2_ssid",
    "wifi_chip1_ssid1_switch_onoff",
    "wifi_chip2_ssid1_switch_onoff",
    "wifi_chip1_ssid2_switch_onoff",
    "wifi_chip2_ssid2_switch_onoff",
    "Z5g_SINR",
    "station_ip_addr",
    "opms_wan_mode",
    "opms_wan_auto_mode",
    "loginfo",
    "ppp_status",
    "ethernet_port_specified",
    "modem_main_state", 
    "puknumber", 
    "pinnumber", 
    "opms_wan_mode", 
    "psw_fail_num_str", 
    "login_lock_time", 
    "SleepStatusForSingleChipCpe"
]

single_cmd_list = [
    "queryAccessPointInfo",
]
"""


def set_logger(log_level, log_file=None):
    """设置日志级别和日志文件（如果提供）"""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    log_handlers = []

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    log_handlers.append(console_handler)

    # 如果提供了日志文件，创建文件处理器
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        log_handlers.append(file_handler)

    # 配置根日志记录器
    logging.basicConfig(
        level=numeric_level,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=log_handlers,
        force=True,
    )

    logger.setLevel(numeric_level)
    logger.info(f"日志级别设置为: {log_level}")
    if log_file:
        logger.info(f"日志将写入文件: {log_file}")


def prepare_params(args: list) -> Dict[str, str]:
    if len(args) == 0:
        return {}
    params: Dict[str, Any] = {
        "isTest": False,
    }
    if len(args) == 1:
        params["cmd"] = args[0]
    else:
        params["cmd"] = ",".join(args)
        params["multi_data"] = 1
    params["_"] = str(int(time.time() * 1000))
    logger.debug(f"get request params: {params}")
    return params


def send(req: Request, *, try_time: int = 3) -> Optional[Response]:
    try:
        status = verify_session()
    except ServerError as e:
        return None
    if not status and try_time > 0:
        logger.info("Session expired, re-login.")
        login()

    logger.debug(f"send request: {req.url}")
    logger.debug(f"send request method: {req.method}")
    logger.debug(f"send request params: {req.params}")
    logger.debug(f"send request data: {req.data}")
    logger.debug(f"send request headers: {req.headers}")
    logger.debug(f"send request cookies: {session.cookies.get_dict()}")
    try:
        res = session.send(req.prepare(), timeout=5)
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None
    if res.status_code == 401 and try_time > 0:
        relogin = False
        while not relogin:
            if try_time <= 0:
                logger.error("Failed to re-login.")
                return None
            logger.info(f"Session expired, re-login. {try_time} times left.")
            try_time -= 1
            relogin = login()
        if "_" in req.params:
            req.params["_"] = str(int(time.time() * 1000))
        return send(req, try_time=try_time)
    elif res.status_code != 200:
        logger.error(f"Request failed: {res.status_code}")
        return None
    return res


def verify_session():
    cmd = [
        "opms_wan_mode",
        "opms_wan_auto_mode",
        "loginfo",
        "ppp_status",
        "ethernet_port_specified",
    ]
    try:
        res = session.get(url=API_GET_URL, params=prepare_params(cmd), headers=HEADERS)
    except Exception as e:
        logger.error("Failed to verify session {e}")
        return False
    logger.debug(f"verify session {res.url}:")
    logger.debug(f"status code: {res.status_code}")
    logger.debug(f"response: {res.text}")
    logger.debug(f"cookie: {session.cookies.get_dict()}")
    if res.status_code != 200:
        raise ServerError("The server is not responding.")
    elif res.json().get("loginfo") == "ok":
        return True
    else:
        return False


def login():
    # get param LD
    cmd = ["LD"]
    req = Request(
        method="GET",
        url=API_GET_URL,
        params=prepare_params(cmd),
        headers=HEADERS,
    )
    logger.debug(f"getting LD param")
    res: Optional[Response] = send(req, try_time=0)
    if res is None:
        logger.error("Failed to get response from the server.")
        return False
    LD: str = res.json().get("LD")
    logger.debug(f"LD param: {LD}")
    if not LD:
        logger.error("Failed to get LD param.")
        return False

    # Construct login request
    form = {
        "isTest": False,
        "goformId": "LOGIN",
    }
    form["password"] = (
        sha256(
            (sha256(password.encode("utf-8")).hexdigest().upper() + LD).encode("utf-8")
        )
        .hexdigest()
        .upper()
    )
    # res = session.post(url=API_SET_URL, data=form, headers=HEADERS)
    req = Request(
        method="POST",
        url=API_SET_URL,
        data=form,
        headers=HEADERS,
    )
    res = send(req, try_time=0)
    if res is None:
        logger.error("Failed to get response from the server.")
        return False

    if res.json().get("result") == 0:
        logger.info("Login successful.")
        return True
    else:
        logger.error("Login failed.")
        return False


def get_ipv6_addr() -> Optional[str]:
    cmd = ["ipv6_wan_ipaddr"]
    req = Request(
        method="GET",
        url=API_GET_URL,
        params=prepare_params(cmd),
        headers=HEADERS,
    )
    res = send(req)
    if res is None:
        logger.error("Failed to get response from the server.")
        return None
    else:
        ipv6_addr = res.json().get("ipv6_wan_ipaddr")
        logger.info(f"Current WAN IPv6 addr: {ipv6_addr}")
        return ipv6_addr


def modify_const(**kwargs):
    """修改常量值"""
    global API_GET_URL, API_SET_URL, host, password
    if "host" in kwargs and kwargs["host"]:
        host = kwargs["host"]
    if "port" in kwargs and kwargs["port"]:
        host = f"{host}:{kwargs['port']}"
    API_GET_URL = host + goform_get_path
    API_SET_URL = host + goform_set_path
    HEADERS["Referer"] = host + "/index.html"
    if "password" in kwargs and kwargs["password"]:
        password = kwargs["password"]


operations = {
    "login": login,
    "ipv6": get_ipv6_addr,
}

if __name__ == "__main__":
    # 解析命令行参数
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="中兴F50操作脚本")
    parser.add_argument(
        "operation", type=str, help="要执行的操作（login, get_ipv6_addr 等）"
    )
    parser.add_argument("password", type=str, help="登录密码")
    parser.add_argument(
        "-H", "--host", type=str, default=host, help="路由器的主机名或IP地址"
    )
    parser.add_argument("-p", "--port", type=int, default=80, help="路由器的端口号")
    parser.add_argument(
        "--LOG_LEVEL",
        type=str,
        default="ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="日志级别",
    )
    parser.add_argument("--log_file", type=str, help="日志文件路径")

    args = parser.parse_args()

    # 设置日志级别和文件
    set_logger(args.LOG_LEVEL, args.log_file)

    if args.host:
        host = args.host
    if args.port:
        host = f"{host}:{args.port}"
    API_GET_URL = host + goform_get_path
    API_SET_URL = host + goform_set_path

    password = args.password

    # 根据操作选择执行的函数

    if args.operation in operations:
        result = operations[args.operation]()
        if result is not None:
            print(result)
    else:
        logger.error(f"未知操作: {args.operation}")
        logger.info("可用操作: {"+ ", ".join(operations.keys()) + "}")
        sys.exit(1)
