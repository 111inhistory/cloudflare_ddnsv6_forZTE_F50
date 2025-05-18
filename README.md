# Cloudflare_DDNSv6_for_ZTE_F50

This project is used to dynamic change DNS Records of ZTE F50.

Thanks [termux-cloudflare-ddns-script](https://github.com/xiongnemo/termux-cloudflare-ddns-script) for the reference.

## Usage

```bash
usage: main.py [-h] -a API_KEY -z ZONE_NAME -n SUBDOMAIN [-H ROUTER_HOST] [-p ROUTER_PORT] [-t REFRESH_TIME] [--LOG_LEVEL {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
               [--log_file LOG_FILE] [--no_exit]
               router_password

Cloudflare DDNS IPv6更新工具

positional arguments:
  router_password       路由器登录密码

options:
  -h, --help            show this help message and exit

必选参数:
  -a API_KEY, --api_key API_KEY
                        Cloudflare API密钥
  -z ZONE_NAME, --zone_name ZONE_NAME
                        域名区域名称，如example.com
  -n SUBDOMAIN, --subdomain SUBDOMAIN
                        子域名，如www

可选参数:
  -H ROUTER_HOST, --router_host ROUTER_HOST
                        路由器IP地址
  -p ROUTER_PORT, --router_port ROUTER_PORT
                        路由器端口号
  -t REFRESH_TIME, --refresh_time REFRESH_TIME
                        刷新时间（秒），默认60秒
  --LOG_LEVEL {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        日志级别
  --log_file LOG_FILE   日志文件路径
  --no_exit             不退出程序
```

Note: port `8080` should be used when the scripts is running in F50 itself.

## Setup in F50 Termux

1. Install `Termux` and `Termux:Boot` (if you want to start when F50 boots) and give them permissions.
2. install Python in termux with: `pkg install python git` and install necessary modules through `pip install cloudflare requests`.
   - You may encounter some issues when install Python module `pydantic-core`. Solution is to install with TUR's pypi and you may need to manually install all dependencies.
3. run:

```bash
git clone https://github.com/111inhistory/cloudflare_ddnsv6_for_ZTE_F50.git

cd cloudflare_ddnsv6_for_ZTE_F50
```

4. Start the tool.

```bash
python main.py <your password of web F50> -a <you api key> -z <your domain> -n <subdomain, like www> -p <port> -t <time> --LOG_LEVEL <log level> --log_file <log file>
```

5. (If start when F50 boots) Create a script to automatically run when booted.

```bash
mkdir -p ~/.termux/boot

nano ~/.termux/boot/boot.sh
```

Then write:

```bash
termux-wake-lock

nohup python ~/cloudflare_ddnsv6_for_ZTE_F50/main.py <arguments>
```

Save and Exit.
