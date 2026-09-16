#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 多 URL 探测 (gstatic 204 / cloudflare trace) 
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (吞吐量不足)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
"""

import os
import re
import io
import sys
import json
import time
import uuid
import base64
import shutil
import socket
import zipfile
import tarfile
import threading
import platform
import subprocess
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

SOURCE_URLS = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",      # 36926 节点
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",           # 21299 节点
    "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",                                       # 5544 节点
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",           # 3913 节点
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",                          # 2139 节点
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",                                       # 2000 节点
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",                                              # 1648 节点
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt", # 1558 节点
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",                             # 1541 节点
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt",                                           # 1000 节点
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",                                 # 574 节点
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",                           # 504 节点
    "https://node.freeclashnode.com/uploads/2026/09/1-20260915.txt",                                                # 280 节点
    "https://node.freeclashnode.com/uploads/2026/09/0-20260915.txt",                                                # 273 节点
    "https://node.freeclashnode.com/uploads/2026/09/0-20260914.txt",                                                # 271 节点
    "https://node.freeclashnode.com/uploads/2026/09/1-20260914.txt",                                                # 268 节点
    "https://www.ermao.net/sub/v2ray/ermao.net",                                                                    # 253 节点
    "https://wild-cloud-9893.heleimail.workers.dev",                                                                # 199 节点
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",         # 199 节点
    "https://open.heleimail.workers.dev/",                                                                          # 150 节点
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY.txt",                                    # 149 节点
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",                               # 100 节点
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt",                                        # 100 节点
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",              # 70 节点
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",                    # 23 节点
    "https://raw.githubusercontent.com/freefq/free/master/v2",                                                      # 15 节点
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",                # 3 节点
]

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
# ★ 性能/严格筛选参数：保持原三阶段结构，只把明显慢、死、危险节点更早淘汰
PROBE_TIMEOUT          = 7.0
PROBE_RETRY_TIMEOUT    = 2.5
PORT_KNOCK_TIMEOUT     = 1.5
IP_ECHO_TIMEOUT        = 4.0
SPEED_TEST_BYTES       = 1_000_000
SPEED_TEST_BUDGET      = 3.5
SPEED_MIN_BYTES_PER_S  = 70_000
SPEED_IDLE_TIMEOUT     = 1.8
MAX_ACCEPT_LATENCY_MS  = 2500
REQUIRE_EXIT_IP        = True
DROP_PORT_KNOCK_FAIL   = True
DROP_INSECURE_TLS      = True
DROP_PROXY_EXIT        = True
DROP_HOSTING_EXIT     = False
SCAM_DROP_SCORE        = 90
SCAM_DOWNGRADE_SCORE   = 75
PREFILTER_WORKERS      = 128
RISK_WORKERS_SCAM      = 12
RISK_WORKERS_VERIFY    = 8
IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
LIVENESS_URLS = [                    # 活性探测 URL (全部要求代理链路完整)
    "https://www.gstatic.com/generate_204",       # 实测 204 OK
    "https://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
SPEED_TEST_URLS = [               # 测速端点多路 (实测部分节点商屏蔽 speed.cloudflare.com)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点
MAX_WORKERS_TEST    = 64            # 同时 sing-box 实测节点数 (Azure 2C7G 实测 24→48 稳定; sing-box 单实例 < 30MB)
MAX_WORKERS_FETCH   = 12
MAX_WORKERS_CLASSIFY = 48

# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    54866,  # Parsebian/HydraTransit 类
    45899,  # VNPT 云? 标记为 IDC
    # ★ 实测漏网: 收购家宽段/伪装 DSL rDNS 的云边网络 (ip-api proxy=true 案例补充)
    62610,  # Zenlayer (AS62610, rDNS 带 dsl.speakeasy.net 但 proxy=true)
    60205,  # 62610 关联段
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
}

# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def atomic_write_text(path: str, content: str):
    """原子覆盖输出，避免订阅客户端读到半截文件。"""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def atomic_write_bytes(path: str, data: bytes):
    """原子覆盖二进制输出。"""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True,encoding="utf-8", timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err = None
        # 重试 2 次 (网络抖动/GFW 间歇性重置; 退避 3s)
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_nodes_from_text(r.text)
                    return url, got, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}

def resolve_host(host: str) -> str:
    """DoH 解析（缓存）；失败再系统 DNS。"""
    if not host or is_ip_literal(host):
        return host or ""
    host = host.strip().lower()
    cached = _DNS_CACHE.get(host)
    if cached:
        return cached
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=3.0)
        if r.status_code == 200:
            for a in (r.json().get("Answer") or []):
                if a.get("type") == 1 and a.get("data"):
                    ip=a["data"]; _DNS_CACHE[host]=ip; return ip
    except Exception:
        pass
    try:
        ip=socket.getaddrinfo(host,None,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        _DNS_CACHE[host]=ip
        return ip
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """快速 TCP 预检；QUIC 直接进入 sing-box。"""
    if protocol_type in ("hysteria2", "tuic"):
        return True
    ip=resolve_host(server)
    if not ip:
        return False
    try:
        with socket.create_connection((ip,port),timeout=PORT_KNOCK_TIMEOUT):
            return True
    except (OSError,TimeoutError):
        return False


def prefilter_candidates(candidates: list) -> list:
    """并行预检；DNS/TCP 明确失败直接淘汰，避免浪费 sing-box。"""
    if not candidates: return []
    print(f"[*] 端口/DNS 快速预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed,failed=[],[]
    def _knock(item):
        raw,outbound,server,port,proto=item
        return item,knock_port(server,port,proto)
    workers=min(PREFILTER_WORKERS,max(8,len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs=[ex.submit(_knock,it) for it in candidates]
        for fut in as_completed(futs):
            item,ok=fut.result()
            (passed if ok else failed).append(item)
    print(f"[+] 预检通过: {len(passed)} | DNS/TCP 不通: {len(failed)}")
    return passed if DROP_PORT_KNOCK_FAIL else passed+failed




# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    front = os.environ.get("FRONT_PROXY", "").strip()
    if front and not chain_relay:
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def test_single_node(item, keep_alive_check=True):
    """单节点真实测活：先淘汰慢/死/无出口/高风险，再做测速。"""
    raw,outbound,server,port,proto=item
    socks_port=_alloc_socks_port()
    task_id=uuid.uuid4().hex[:10]
    cfg_path=os.path.join(RUNTIME_DIR,f"sb_{task_id}.json")

    if DROP_INSECURE_TLS:
        tls=outbound.get("tls") or {}
        if tls.get("enabled") and tls.get("insecure"):
            return None

    chain_out=None
    chain_json=os.environ.get("CHAIN_RELAY_OUT","").strip()
    if chain_json:
        try: chain_out=json.loads(chain_json)
        except Exception: chain_out=None

    config=build_test_config(outbound,socks_port,chain_relay=chain_out)
    with open(cfg_path,"w",encoding="utf-8") as f:
        json.dump(config,f,separators=(",",":"))

    exe=SINGBOX_BIN+(".exe" if os.name=="nt" else "")
    creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
    proc=None
    try:
        try:
            chk=subprocess.run([exe,"check","-c",cfg_path],capture_output=True,text=True,encoding="utf-8",
                              timeout=8,creationflags=creationflags)
            if chk.returncode!=0: return None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            pass

        try:
            proc=subprocess.Popen([exe,"run","-c",cfg_path],stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,creationflags=creationflags)
            deadline=time.monotonic()+4.0
            while time.monotonic()<deadline:
                if proc.poll() is not None: return None
                try:
                    with socket.create_connection(("127.0.0.1",socks_port),timeout=0.25):
                        break
                except OSError:
                    time.sleep(0.08)
            else:
                return None

            proxies={"http":f"socks5h://127.0.0.1:{socks_port}",
                     "https":f"socks5h://127.0.0.1:{socks_port}"}

            # 1) 活性
            latency_ms=99999
            alive=False
            for i,url in enumerate(LIVENESS_URLS):
                timeout=PROBE_TIMEOUT if i==0 else PROBE_RETRY_TIMEOUT
                t0=time.monotonic()
                try:
                    r=PROBE_SESSION.get(url,proxies=proxies,timeout=timeout,
                                        allow_redirects=False,verify=True)
                    if r.status_code in (204,200):
                        latency_ms=int((time.monotonic()-t0)*1000)
                        alive=True
                        break
                except requests.RequestException:
                    pass
            if not alive or latency_ms>MAX_ACCEPT_LATENCY_MS:
                return None

            # 2) 出口 IP
            exit_ip=exit_country=exit_asn=exit_asn_org=exit_isp=None
            for url in IP_ECHO_URLS:
                try:
                    r=PROBE_SESSION.get(url,proxies=proxies,timeout=IP_ECHO_TIMEOUT,
                                        allow_redirects=False,verify=True)
                    if r.status_code!=200: continue
                    j=r.json()
                    ip=str(j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                    try: ipaddress.ip_address(ip)
                    except ValueError: continue
                    exit_ip=ip
                    if url.startswith("https://api.ip.sb"):
                        exit_country=j.get("country_code")
                        exit_asn=j.get("asn")
                        exit_asn_org=j.get("asn_organization") or j.get("organization") or ""
                        exit_isp=j.get("isp") or j.get("organization") or ""
                    elif url.startswith("https://ipinfo.io"):
                        exit_country=(j.get("country") or "").upper() or None
                        org=j.get("org") or ""
                        mm=re.match(r"^AS(\d+)\s+(.*)",org)
                        if mm: exit_asn=int(mm.group(1)); exit_asn_org=mm.group(2)
                        exit_isp=org
                    else:
                        exit_country=(j.get("countryCode") or "").upper() or None
                        exit_asn=j.get("as")
                        exit_asn_org=j.get("asname") or j.get("org") or ""
                        exit_isp=j.get("isp") or j.get("org") or ""
                    break
                except (requests.RequestException,ValueError,json.JSONDecodeError):
                    continue
            if REQUIRE_EXIT_IP and not exit_ip:
                return None

            # 3) TLS/证书风险
            mitm_risk=False
            try:
                r=PROBE_SESSION.get("https://www.gstatic.com/generate_204",proxies=proxies,
                                    timeout=PROBE_RETRY_TIMEOUT,verify=True,allow_redirects=False)
                if r.status_code not in (204,200):
                    mitm_risk=r.status_code in (301,302,403,407,502,503) or bool(r.content)
            except requests.exceptions.SSLError:
                mitm_risk=True
            except requests.RequestException:
                pass
            if mitm_risk: return None

            is_warp=False
            try:
                r=PROBE_SESSION.get(TRACE_URL,proxies=proxies,timeout=PROBE_RETRY_TIMEOUT,
                                    verify=True,allow_redirects=False)
                if r.status_code==200 and re.search(r"^warp=on",r.text,re.M):
                    is_warp=True
            except requests.RequestException:
                pass

            # 4) 快速测速
            speed_bps=0
            for speed_url in SPEED_TEST_URLS:
                downloaded=0
                t_speed=time.monotonic()
                last_chunk=t_speed
                try:
                    with PROBE_SESSION.get(speed_url,proxies=proxies,
                                            timeout=(3.0,SPEED_TEST_BUDGET),
                                            stream=True,allow_redirects=False) as r:
                        if r.status_code!=200: continue
                        for chunk in r.iter_content(chunk_size=65536):
                            now=time.monotonic()
                            if chunk:
                                downloaded+=len(chunk); last_chunk=now
                            if now-t_speed>=SPEED_TEST_BUDGET or now-last_chunk>=SPEED_IDLE_TIMEOUT:
                                break
                    elapsed=max(time.monotonic()-t_speed,0.001)
                    if downloaded:
                        speed_bps=int(downloaded/elapsed)
                        break
                except requests.RequestException:
                    continue
            if speed_bps<SPEED_MIN_BYTES_PER_S:
                return None

            return {"raw":raw,"server":server,"port":port,"proto":proto,"outbound":outbound,
                    "alive":True,"latency_ms":latency_ms,"exit_ip":exit_ip,
                    "exit_country_online":exit_country,"exit_asn_online":exit_asn,
                    "exit_asn_org_online":(exit_asn_org or "")[:120],
                    "exit_isp_online":(exit_isp or "")[:120],"mitm_risk":False,
                    "is_warp":is_warp,"speed_bps":speed_bps,"is_stalled":False}
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                try: proc.wait(timeout=2)
                except Exception: pass
    except Exception:
        return None
    finally:
        try:
            if os.path.exists(cfg_path): os.remove(cfg_path)
        except OSError: pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    if not candidates: return []
    results=[]; done_count=0
    workers=min(MAX_WORKERS_TEST,max(8,len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs={ex.submit(test_single_node,it):it for it in candidates}
        for fut in as_completed(futs):
            done_count+=1
            try: r=fut.result()
            except Exception: r=None
            if r: results.append(r)
            if done_count%40==0 or done_count==len(candidates):
                print(f"[*] 测活进度: {done_count}/{len(candidates)}, 当前通过 {len(results)}")
    print(f"[+] 测活完成: 可用 {len(results)} | 测活阶段淘汰 {len(candidates)-len(results)}")
    return results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile") and c >= 60:
            res_candidates[(r["server"].lower(), r["port"], r["proto"])] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"]) not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        for key, r in res_candidates.items():
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                chain_dead.append(r)
                continue
            recheck = test_single_node(item)
            if recheck and recheck.get("alive") and not recheck.get("is_stalled"):
                chain_alive.append(r)
            else:
                chain_dead.append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    for r in chain_dead:
        r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min → 1500 IP/min)"""
    info = {}
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        if bi < total_batches:
            time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) CDN / Anycast 网段 (硬判据)
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict"""
    t = node.get("type")
    server, port = node["server"], node["server_port"]
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    no_exit_ip = []
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (仅本轮实际测活节点 {len(test_results)} 个)")

    ip_api_info = {}
    scam_scores = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r["speed_bps"],
            "mitm_risk": r["mitm_risk"],
            "is_stalled": r["is_stalled"],
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 ──
    # MITM 劫持节点: 高危, 直接丢弃 (204 能通但证书被劫持 = 中间人)
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)
    # 断流节点已无 (在 liveness 阶段淘汰), 但 double-check
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped}")

    # ── Scamalytics 风控评分 (免费 HTML, 逐个; 只查家宽候选 + 抽样普通节点) ──
    # 所有可导出的出口 IP 均查一次；同 IP 只查询一次，强化风险筛查。
    scam_candidates = {n["exit_ip"] for n in safe_nodes if n.get("exit_ip")}
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽候选出口 IP ...")
        def _scam(ip):
            return ip, scamalytics_fraud_score(ip)
        with ThreadPoolExecutor(max_workers=RISK_WORKERS_SCAM) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, ipapi_is_verify(ip)
        with ThreadPoolExecutor(max_workers=RISK_WORKERS_VERIFY) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if n["net_type"] not in ("residential", "mobile"):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # ip-api proxy=true：匿名代理/VPN/Tor 等风险出口直接剔除。
    if DROP_PROXY_EXIT:
        before_proxy=len(safe_nodes)
        safe_nodes=[n for n in safe_nodes if ip_api_info.get(n.get("exit_ip"),{}).get("proxy") is not True]
        if before_proxy-len(safe_nodes):
            print(f"[*] proxy/VPN/Tor 风险出口剔除: {before_proxy-len(safe_nodes)} 个")

    # 风险分 ≥90 全区剔除；75-89 的家宽候选降级普通区。
    downgraded = 0
    high_risk_dropped = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        if sc >= SCAM_DROP_SCORE:
            n["_risk_drop"] = True
            high_risk_dropped += 1
        elif n["net_type"] in ("residential", "mobile") and sc >= SCAM_DOWNGRADE_SCORE:
            n["net_type"] = "datacenter"
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥{SCAM_DOWNGRADE_SCORE}) 家宽候选降级: {downgraded} 个")
    if high_risk_dropped:
        before_risk=len(safe_nodes)
        safe_nodes=[n for n in safe_nodes if not n.get("_risk_drop")]
        print(f"[*] 极高风险节点 (fraud≥{SCAM_DROP_SCORE}) 剔除: {before_risk-len(safe_nodes)} 个")

    # ── 去重 (同出口IP+端口 只留最快) ──
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped})")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n["confidence"] >= 60:
            if n.get("raw") in chain_failed_raws:
                n["net_type"] = "datacenter"
                n["confidence"] = 70
                continue
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    non_residential = [n for n in unique_nodes if n not in residential]
    print(f"[*] 家宽/移动网络节点: {len(residential)} | 普通(机房/CDN): {len(non_residential)}")

    # 排序: 家宽在前, 延迟升序
    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, x["latency_ms"]))
    residential.sort(key=lambda x: x["latency_ms"])
    non_residential.sort(key=lambda x: x["latency_ms"])
    # ★ 链式复测双跳失败的家宽 → 降级普通区 (v2rayN 链式场景不可靠)
    #    保留在总订阅/国家订阅里 (直连场景仍可用), 只是退出家宽专区

    # 重建 outbound (测活阶段的 outbound 已验证可用); 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        parsed = parse_node_uri(n["raw"])
        if parsed:
            ob = parsed[0]
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    is_res = item["net_type"] in ("residential", "mobile") and (item["confidence"] >= 60 or force_residential)
    tag = ""
    if is_res:
        tag = " (家宽)" if item["net_type"] == "residential" else " (移动家宽)"
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    return f"{flag} {cname} {idx:02d}{tag}{risk_tag}"


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            # ★ 输出前始终从本轮 raw URI 重新解析，避免旧 outbound/旧链接残留。
            parsed = parse_node_uri(item["raw"])
            if not parsed:
                continue
            ob = parsed[0]
            ob.pop("detour", None)
            item["outbound"] = ob
            link = outbound_to_v2ray_link(ob, name)
            if not link:
                continue
            links.append(link)
            cp = outbound_to_clash(ob, name)
            if cp:
                proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    # 1) 全量
    all_links, all_proxies, all_sb = build_group(unique_nodes)
    atomic_write_bytes(os.path.join(OUTPUT_DIR, "v2ray.txt"),
                       base64.b64encode("\n".join(all_links).encode()))
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_sb, os.path.join(OUTPUT_DIR, "singbox.json"))

    # 2) 家宽总订阅
    res_links, res_proxies, res_sb = build_group(residential, force_res=True)
    atomic_write_bytes(os.path.join(OUTPUT_DIR, "residential.txt"),
                       base64.b64encode("\n".join(res_links).encode()))
    if res_proxies:
        export_clash_yaml(res_proxies, os.path.join(OUTPUT_DIR, "residential-clash.yaml"))
        export_singbox_json(res_sb, os.path.join(OUTPUT_DIR, "residential-singbox.json"))
    else:
        for fn in ("residential-clash.yaml", "residential-singbox.json"):
            p = os.path.join(OUTPUT_DIR, fn)
            if os.path.exists(p):
                os.remove(p)

    # 3) 按国家 - 普通区
    shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    by_cc = {}
    for n in non_residential:
        by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in by_cc.items():
        l, p, s = build_group(lst)
        atomic_write_bytes(os.path.join(COUNTRY_DIR, f"{cc}.txt"),
                           base64.b64encode("\n".join(l).encode()))
        export_clash_yaml(p, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json"))

    # 4) 按国家 - 家宽区
    shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    res_by_cc = {}
    for n in residential:
        res_by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in res_by_cc.items():
        l, p, s = build_group(lst, force_res=True)
        atomic_write_bytes(os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"),
                           base64.b64encode("\n".join(l).encode()))
        export_clash_yaml(p, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"))

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽 {len(res_links)}")
    return len(all_links), len(res_links)


def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "OgdenThomas/freesub").strip()
    cache_bust = str(int(time.time()))
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "OgdenThomas", "freesub"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/{cc}.txt?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/{cc}.txt?v={cache_bust})"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/clash-{cc}.yaml?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/clash-{cc}.yaml?v={cache_bust})"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/singbox-{cc}.json?v={cache_bust}) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/singbox-{cc}.json?v={cache_bust})"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽)`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v{SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/clash.yaml?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/clash.yaml?v={cache_bust}) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/v2ray.txt?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/v2ray.txt?v={cache_bust}) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/singbox.json?v={cache_bust}) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/singbox.json?v={cache_bust}) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽判定六重信号: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 60+ 国家主流民用运营商) ⑤ rDNS/ISP 名称特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除)。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **测活标准**：节点必须通过 ① 端口预检 ② sing-box 实际隧道 3 个 generate_204 探测 ③ 真实出口 IP 穿透获取 ④ Cloudflare 5MB 限时下载 (吞吐 ≥ 70KB/s) ⑤ TLS 证书校验非 MITM, 方可入库。
3. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    atomic_write_text(os.path.join(BASEDIR, "README.md"), readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1. 抓取
    raw_nodes = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前强去重 (凭据指纹去重: 同 凭据+目标+协议 只测一次)
    # 注意：这里的去重仅用于减少测活次数。
    # 严格出库模式下，重复 URI 不做“结果回填”，避免一个真实测活节点
    # 被扩展成大量未独立验证的订阅节点。最终出库只允许本轮实际测过的节点。
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹: uuid/password 各协议的核心身份字段 (vless uuid / vmess id+alterId /
    #               trojan password / ss 2022密钥 / hy2 auth / tuic uuid+passwd / anytls password)
    #     完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次
    def cred_fingerprint(outbound: dict, proto: str) -> str:
        try:
            if proto == "vless":
                return f"{outbound.get('uuid','')}"
            if proto == "vmess":
                return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
            if proto == "trojan":
                return f"{outbound.get('password','')}"
            if proto == "shadowsocks":
                return f"{outbound.get('method','')}|{outbound.get('password','')}"
            if proto == "hysteria2":
                return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
            if proto == "tuic":
                return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
            if proto == "anytls":
                return f"{outbound.get('password','')}"
            return json.dumps({k: v for k, v in outbound.items()
                              if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        except Exception:
            return ""  # 指纹失败 → 不合并 (宁慢不错)

    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)  # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count} — 仅减少测活，不回填出库)")
    DEDUP_MAP = seen_keys  # 仅用于统计去重数量；严格模式不用于回填出库
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)

    # 4. 真实测活 (只测去重后的代表节点)
    test_results = run_liveness_test(candidates)

    # 4.5 ★ 严格出库：禁止重复结果回填
    # 测前去重只是性能优化；重复 URI 不代表它们都经过了独立测活。
    # 因此这里不再把代表节点的 alive / latency / exit_ip / risk 结果复制给
    # 其它 URI。这样 classify_and_export() 接收到的 test_results 就是
    # “本轮真正被 sing-box 测试过并返回结果”的节点集合。
    #
    # 这一步是解决“实际测活一百多个，但订阅突然膨胀到数百/上千节点”的关键。
    if DEDUP_MAP:
        duplicate_uris = sum(max(0, len(v) - 1) for v in DEDUP_MAP.values())
        if duplicate_uris:
            print(f"[*] 严格出库: 跳过 {duplicate_uris} 个重复 URI 回填，只导出本轮实际测活节点")

    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return
    total, res = export_all(unique_nodes, residential, non_residential)
    update_readme(total, res)


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析成功 {len(candidates)} → 真活 {len(test_results)} → 去重后 {len(unique_nodes)} → 家宽 {len(residential)}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")


if __name__ == "__main__":
    main()
