import time
import login
import cloudflare
import logging
import argparse

from typing import Any, Optional
from logging import handlers

# 获取logger
logger = logging.getLogger(__name__)
MAX_LOG_SIZE = 1024 * 1024 * 2  # 2MB
BACKUP_COUNT = 5  # Max 5 backup files of logs

RRTYPE = "AAAA"
refresh_time = 60
zone_id = {}
dns_id = {}


def set_logger(log_level: str, log_file=None):
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
        # file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler = handlers.RotatingFileHandler(
            log_file, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
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


def create_client(api_token: str) -> cloudflare.Cloudflare:
    try:
        client = cloudflare.Cloudflare(api_token=api_token)
    except cloudflare.CloudflareError as e:
        logger.error("[create_client] Verify token failed. Please check your token")
        logger.debug(f"[create_client] Error: {e}")
        logger.debug(f"[create_client] api_token: {api_token}")
        exit(1)
    return client


def get_zone_id(client: cloudflare.Cloudflare, zone: str) -> str:
    global zone_id
    if zone in zone_id:
        return zone_id[zone]
    result = client.zones.list(name=zone)
    if result.result:
        zone_id = result.result[0].id
        logger.debug(f"[get_zone_id] Zone id of {zone} found {zone_id}")
        return zone_id
    logger.error(f"[get_zone_id] Get zone id of {zone} failed. Please check your zone name")
    return ""


def get_dns_id(
    client: cloudflare.Cloudflare, zone_id: str, dns_name: str
) -> Optional[str]:
    global dns_id
    if dns_name in dns_id:
        return dns_id[dns_name]
    dns_records = client.dns.records.list(zone_id=zone_id, name=dns_name, type=RRTYPE)  # type: ignore
    if not dns_records:
        return None
    result = dns_records.result
    for i in result:
        if i.name == dns_name and i.type == RRTYPE:
            logger.debug(f"[get_dns_id] DNS id of {dns_name} found {i.id}")
            return i.id
    return None


def get_dns_record(client: cloudflare.Cloudflare, zone_id: str, dns_id: str) -> Any:
    result = client.dns.records.get(zone_id=zone_id, dns_record_id=dns_id)

    if not result:
        return None
    if result.id == dns_id and result.type == RRTYPE:
        logger.debug(f"[get_dns_record] DNS record {dns_id} found")
        logger.debug(f"[get_dns_record] DNS record {dns_id} content: {result.content}")
        logger.debug(f"[get_dns_record] DNS record {dns_id} name: {result.name}")
        logger.debug(f"[get_dns_record] DNS record {dns_id} type: {result.type}")
        logger.debug(f"[get_dns_record] DNS record {dns_id} ttl: {result.ttl}")
        logger.debug(f"[get_dns_record] DNS record {dns_id} proxied: {result.proxied}")
        logger.debug(f"[get_dns_record] DNS record {dns_id} comment: {result.comment}")
        return result
    return None


def create_dns_record(client: cloudflare.Cloudflare, zone_id, dns_name, ip_address):
    client.dns.records.create(
        zone_id=zone_id,
        name=dns_name,
        type=RRTYPE,
        content=ip_address,
        ttl=60,
        proxied=False,
        comment="Created for IPv6 DDNS",
    )


def do_dns_update(
    client: cloudflare.Cloudflare,
    zone_name,
    dns_name,
):
    ip_addr = get_ipv6_address()
    if not ip_addr:
        logger.error("[update_dns] Failed to get IPv6 address")
        return False
    zone_id = get_zone_id(client, zone_name)
    if not zone_id:
        logger.error(f"[update_dns] Failed to get zone id for {zone_name}")
        return False
    dns_id = get_dns_id(client, zone_id, dns_name)
    if not dns_id:
        logger.info(f"[update_dns] DNS record {dns_name} not found, creating a new one")
        create_dns_record(client, zone_id, dns_name, ip_addr)
        dns_id = get_dns_id(client, zone_id, dns_name)
        if not dns_id:
            logger.error(f"[update_dns] Failed to create DNS record {dns_name}")
            return False
    record = get_dns_record(client, zone_id, dns_id)
    if record.content == ip_addr:
        logger.info(f"[update_dns] DNS record {dns_name} is up to date")
        return True
    else:
        logger.info(f"[update_dns] DNS record {dns_name} is not up to date, updating it")
    client.dns.records.edit(
        zone_id=zone_id,
        dns_record_id=dns_id,
        content=ip_addr,
    )
    logger.info(f"[update_dns] DNS record {dns_name} updated to {ip_addr} from {record.content}")
    return True


def get_ipv6_address() -> Optional[str]:
    return login.get_ipv6_addr()


def retry_dns_update(client, zone_name, dns_name):
    """
    带有重试机制的DNS更新函数
    重试3次，每次间隔分别为5秒、10秒、20秒
    """
    retry_count = 0
    retry_intervals = [5, 10, 20]
    max_retries = len(retry_intervals)
    success = False

    while retry_count <= max_retries and not success:
        try:
            if retry_count > 0:
                logger.info(f"[retry_dns_update] Retrying DNS update ({retry_count}/{max_retries})")
            success = do_dns_update(client, zone_name, dns_name)
            if success:
                logger.info("[retry_dns_update] DNS update success")
            else:
                logger.warning("[retry_dns_update] DNS update failed")
        except Exception as e:
            logger.error(f"[retry_dns_update] DNS update failed: {e}")

        if not success and retry_count < max_retries:
            wait_time = retry_intervals[retry_count]
            logger.info(f"[retry_dns_update] Waiting {wait_time}s to retry")
            time.sleep(wait_time)
        retry_count += 1

    if not success and retry_count > max_retries:
        logger.error("[retry_dns_update] DNS update failed and exceeded max retries")
    return success


def main(
    api_key: str, zone_name: str, subdomain: str, refresh_time: int, no_exit: bool
):
    # 循环运行，当no_exit=True时，即使遇到异常也会继续
    while True:
        try:
            logger.info("[main] Starting DDNS update main loop")
            # 创建Cloudflare客户端
            client = create_client(api_key)

            ipv6_addr = get_ipv6_address()
            dns_name = f"{subdomain}.{zone_name}"

            logger.info(f"[main] DNS name: {dns_name}")
            logger.info(f"[main] Current IPv6 address: {ipv6_addr}")

            # 内部更新循环
            while True:
                if not retry_dns_update(client, zone_name, dns_name) and not no_exit:
                    logger.error("[main] DNS update failed，exiting...")
                    return
                time.sleep(refresh_time)

        except KeyboardInterrupt:
            logger.info("[main] Received keyboard interrupt, exiting...")
            return
        except Exception as e:
            logger.error(f"[main] Found Error: {e}")
            if not no_exit:
                logger.error("[main] Exiting as no_exit is not set...")
                return

            # 当设置了no_exit时，在继续前先等待一定时间
            wait_time = 30  # 失败后等待30秒再重启主循环
            logger.info(f"[main] Restarting main loop in {wait_time} seconds...")
            time.sleep(wait_time)
            logger.info("[main] Restarting main loop...")
            # 继续循环而非递归调用


if __name__ == "__main__":
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Cloudflare DDNS IPv6更新工具")
    parser.add_argument("router_password", type=str, help="路由器登录密码")
    required = parser.add_argument_group("必选参数")
    required.add_argument(
        "-a", "--api_key", type=str, required=True, help="Cloudflare API密钥"
    )
    required.add_argument(
        "-z", "--zone_name", type=str, required=True, help="域名区域名称，如example.com"
    )
    required.add_argument(
        "-n", "--subdomain", required=True, type=str, help="子域名，如www"
    )
    optional = parser.add_argument_group("可选参数")
    optional.add_argument(
        "-H",
        "--router_host",
        type=str,
        default="http://192.168.0.1",
        help="路由器IP地址",
    )
    optional.add_argument(
        "-p", "--router_port", type=int, default=80, help="路由器端口号"
    )
    optional.add_argument(
        "-t", "--refresh_time", type=int, default=60, help="刷新时间（秒），默认60秒"
    )
    optional.add_argument(
        "--LOG_LEVEL",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="日志级别",
    )
    optional.add_argument("--log_file", type=str, help="日志文件路径")
    optional.add_argument(
        "--no_exit", action="store_true", default=False, help="不退出程序"
    )
    args = parser.parse_args()

    # 设置日志级别和文件
    set_logger(args.LOG_LEVEL, args.log_file)

    # 设置路由器连接参数
    login.modify_const(
        host=args.router_host, port=args.router_port, password=args.router_password
    )

    main(args.api_key, args.zone_name, args.subdomain, args.refresh_time, args.no_exit)
