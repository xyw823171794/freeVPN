#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
freeVPN (freeVPN)
=================
多源订阅聚合 -> 协议归一 -> 指纹去重 -> 双层探活 -> Clash/通用订阅 + 本地订阅服务

  L1 探活  纯 TCP 握手延迟 (asyncio 高并发), 秒级筛掉死节点
  L2 探活  拉起 mihomo 内核, 走 /proxies/{name}/delay 真实 HTTP 测速,
           只留"真能出网"的节点 —— 这是池子和普通聚合器的分界线

用法:
  python pool.py fetch                  # 只拉源, 看各源产出
  python pool.py all                    # 全流程 (含 L2)
  python pool.py all --no-l2            # 跳过内核测速, 只做 TCP
  python pool.py serve --port 8787      # 起订阅服务
  python pool.py daemon --interval 30   # 常驻: 定时刷新 + 对外服务
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import concurrent.futures as cf
import hashlib
import html
import ipaddress
import json
import math
import os
import random
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# 先让 security 能被 import —— 打包后它已经在 sys.modules 里, 源码运行时才需要加路径
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
# 同目录安全模块: 输入隔离 / 节点审计 / 进程隔离 / 访问控制 / 分流规则
import security as sec  # noqa: E402
import version as ver  # noqa: E402
# 在线更新: 从项目的 GitHub 仓库拉最新版本(只下载, 不自动执行)
import updater  # noqa: E402

# 打包成 exe 后 __file__ 指向临时解包目录, 所以根目录要问 security 要
ROOT = sec.app_root()

BIN = ROOT / "bin"
OUT = ROOT / "out"
STATE = ROOT / "state"
RAW = STATE / "raw"
SOURCES = sec.find_resource("sources.txt") or (ROOT / "sources.txt")
CACHE = STATE / "cache.json"
KERNEL_DIR = STATE / "kernel"
# 纯地址落盘: 从控制台或 README 复制时极易把 "Clash:" / "|" / 中文说明一起带走,
# 客户端一看开头不是 http 就判"无效的订阅链接"
ADDR_FILE = ROOT / "订阅地址.txt"
# 可选配置文件: 刷新间隔这类设置写在这里, 不用每次记命令行参数
CONF_FILE = ROOT / "pool.conf.json"
# 这几个键不走 argparse(它们配的是分流规则, 不是扫描参数), 由 sec.configure_cn
# 消费 —— 不能让它们出现在"不认识, 已忽略"的告警里
CN_CONF_KEYS = ("cn_mode", "cn_resolve", "cn_ipv6")
# 订阅服务的请求日志 —— 客户端报"导入失败"时, 只有这里能看到它真正请求了什么
ACCESS_LOG = STATE / "access.log"

MIHOMO = sec.find_kernel() or (BIN / "mihomo.exe")
# 控制端口与密钥**不再有模块级常量**。写死过一版 `SECRET = "freevpn"` +
# 固定 19090, 结果任意网页都能拿这个公开密钥改本机内核配置(见 Kernel 的说明)。
# 现在由 Kernel 每次实例化随机生成。

TEST_URL = "http://www.gstatic.com/generate_204"
UA = "clash-verge/v2.2.3 (freeVPN)"

# 单源节点上限, 防止巨型源把整轮拖爆。
# 免费节点真实可用率约 1%, 想多出货只能多测 —— 这个上限直接决定池子规模。
PER_SOURCE_CAP = 2500

# 产物 YAML 允许出现的顶层键。build_clash 生成完会反解自校验,
# 多出任何键都说明有东西往顶层注入(见 _quote 的说明), 一律剔除。
_TOP_LEVEL_KEYS = {
    "mixed-port", "allow-lan", "mode", "log-level", "ipv6", "unified-delay",
    "tcp-concurrent", "find-process-mode", "profile", "dns",
    "proxies", "proxy-groups", "rules",
}


# --------------------------------------------------------------------------
# 地区识别
# --------------------------------------------------------------------------
# (代码, 旗帜, 中文, [英文/别名关键词])
REGION_RULES: list[tuple[str, str, str, list[str]]] = [
    # 国内节点不是翻墙节点, 命中直接丢弃 (回环/内网 IP 另有独立过滤)
    ("CN", "🇨🇳", "中国", ["china", "中国", "北京", "上海", "广州", "深圳", "回国", "国内中转"]),
    ("HK", "🇭🇰", "香港", ["hongkong", "hong kong", "hkg", "hk", "深港", "沪港", "京港", "港"]),
    ("TW", "🇹🇼", "台湾", ["taiwan", "tpe", "twn", "tw", "台灣", "中華電信", "台"]),
    ("JP", "🇯🇵", "日本", ["japan", "tokyo", "osaka", "nrt", "kix", "jp", "东京", "大阪", "日"]),
    ("SG", "🇸🇬", "新加坡", ["singapore", "sgp", "sin", "sg", "狮城", "新加坡"]),
    ("US", "🇺🇸", "美国", ["united states", "usa", "los angeles", "seattle", "san jose",
                            "dallas", "phoenix", "new york", "chicago", "miami", "atlanta",
                            "silicon", "lax", "sjc", "sea", "us", "洛杉矶", "西雅图",
                            "圣何塞", "达拉斯", "纽约", "芝加哥", "迈阿密", "美"]),
    ("KR", "🇰🇷", "韩国", ["korea", "seoul", "icn", "kr", "首尔", "韩"]),
    ("GB", "🇬🇧", "英国", ["united kingdom", "london", "england", "uk", "gb", "伦敦", "英"]),
    ("DE", "🇩🇪", "德国", ["germany", "frankfurt", "de", "fra", "法兰克福", "德"]),
    ("FR", "🇫🇷", "法国", ["france", "paris", "fr", "巴黎", "法"]),
    ("NL", "🇳🇱", "荷兰", ["netherlands", "amsterdam", "nl", "阿姆斯特丹", "荷"]),
    ("CA", "🇨🇦", "加拿大", ["canada", "toronto", "vancouver", "montreal", "ca", "多伦多", "温哥华", "加"]),
    ("AU", "🇦🇺", "澳大利亚", ["australia", "sydney", "melbourne", "au", "悉尼", "澳"]),
    ("RU", "🇷🇺", "俄罗斯", ["russia", "moscow", "ru", "莫斯科", "俄"]),
    ("IN", "🇮🇳", "印度", ["india", "mumbai", "bangalore", "in", "孟买", "印"]),
    ("TR", "🇹🇷", "土耳其", ["turkey", "istanbul", "tr", "伊斯坦布尔", "土"]),
    ("VN", "🇻🇳", "越南", ["vietnam", "vn", "越南", "越"]),
    ("TH", "🇹🇭", "泰国", ["thailand", "bangkok", "th", "曼谷", "泰"]),
    ("MY", "🇲🇾", "马来西亚", ["malaysia", "kuala", "my", "马来", "马"]),
    ("ID", "🇮🇩", "印尼", ["indonesia", "jakarta", "id", "雅加达", "印尼"]),
    ("PH", "🇵🇭", "菲律宾", ["philippines", "manila", "ph", "马尼拉", "菲"]),
    ("AE", "🇦🇪", "阿联酋", ["united arab", "dubai", "ae", "迪拜", "阿联酋"]),
    ("CH", "🇨🇭", "瑞士", ["switzerland", "zurich", "ch", "瑞士"]),
    ("FI", "🇫🇮", "芬兰", ["finland", "helsinki", "fi", "芬兰"]),
    ("SE", "🇸🇪", "瑞典", ["sweden", "stockholm", "se", "瑞典"]),
    ("NO", "🇳🇴", "挪威", ["norway", "oslo", "no", "挪威"]),
    ("DK", "🇩🇰", "丹麦", ["denmark", "copenhagen", "dk", "丹麦"]),
    ("PL", "🇵🇱", "波兰", ["poland", "warsaw", "pl", "波兰"]),
    ("BR", "🇧🇷", "巴西", ["brazil", "sao paulo", "br", "巴西"]),
    ("AR", "🇦🇷", "阿根廷", ["argentina", "ar", "阿根廷"]),
    ("ES", "🇪🇸", "西班牙", ["spain", "madrid", "es", "西班牙"]),
    ("IT", "🇮🇹", "意大利", ["italy", "milan", "it", "米兰", "意大利"]),
    ("IE", "🇮🇪", "爱尔兰", ["ireland", "dublin", "ie", "爱尔兰"]),
    ("AT", "🇦🇹", "奥地利", ["austria", "vienna", "at", "奥地利"]),
    ("CZ", "🇨🇿", "捷克", ["czech", "prague", "cz", "捷克"]),
    ("HU", "🇭🇺", "匈牙利", ["hungary", "budapest", "hu", "匈牙利"]),
    ("RO", "🇷🇴", "罗马尼亚", ["romania", "bucharest", "ro", "罗马尼亚"]),
    ("UA", "🇺🇦", "乌克兰", ["ukraine", "kyiv", "kiev", "ua", "乌克兰"]),
    ("LT", "🇱🇹", "立陶宛", ["lithuania", "lt", "立陶宛"]),
    ("EE", "🇪🇪", "爱沙尼亚", ["estonia", "ee", "爱沙尼亚"]),
    ("LV", "🇱🇻", "拉脱维亚", ["latvia", "lv", "拉脱维亚"]),
    ("MD", "🇲🇩", "摩尔多瓦", ["moldova", "md", "摩尔多瓦"]),
    ("IL", "🇮🇱", "以色列", ["israel", "il", "以色列"]),
    ("SA", "🇸🇦", "沙特", ["saudi", "sa", "沙特"]),
    ("PK", "🇵🇰", "巴基斯坦", ["pakistan", "pk", "巴基斯坦"]),
    ("BD", "🇧🇩", "孟加拉", ["bangladesh", "bd", "孟加拉"]),
    ("KH", "🇰🇭", "柬埔寨", ["cambodia", "kh", "柬埔寨"]),
    ("MM", "🇲🇲", "缅甸", ["myanmar", "mm", "缅甸"]),
    ("MN", "🇲🇳", "蒙古", ["mongolia", "mn", "蒙古"]),
    ("KZ", "🇰🇿", "哈萨克", ["kazakhstan", "kz", "哈萨克"]),
    ("NZ", "🇳🇿", "新西兰", ["new zealand", "auckland", "nz", "新西兰"]),
    ("PT", "🇵🇹", "葡萄牙", ["portugal", "lisbon", "pt", "葡萄牙"]),
    ("GR", "🇬🇷", "希腊", ["greece", "athens", "gr", "希腊"]),
    ("BG", "🇧🇬", "保加利亚", ["bulgaria", "sofia", "bg", "保加利亚"]),
    ("RS", "🇷🇸", "塞尔维亚", ["serbia", "belgrade", "rs", "塞尔维亚"]),
    ("AM", "🇦🇲", "亚美尼亚", ["armenia", "am", "亚美尼亚"]),
    ("GE", "🇬🇪", "格鲁吉亚", ["georgia", "tbilisi", "ge", "格鲁吉亚"]),
    ("CY", "🇨🇾", "塞浦路斯", ["cyprus", "cy", "塞浦路斯"]),
    ("MT", "🇲🇹", "马耳他", ["malta", "mt", "马耳他"]),
    ("LU", "🇱🇺", "卢森堡", ["luxembourg", "lu", "卢森堡"]),
    ("IS", "🇮🇸", "冰岛", ["iceland", "is", "冰岛"]),
    ("SK", "🇸🇰", "斯洛伐克", ["slovakia", "sk", "斯洛伐克"]),
    ("SI", "🇸🇮", "斯洛文尼亚", ["slovenia", "si", "斯洛文尼亚"]),
    ("HR", "🇭🇷", "克罗地亚", ["croatia", "hr", "克罗地亚"]),
    ("MX", "🇲🇽", "墨西哥", ["mexico", "mx", "墨西哥"]),
    ("CL", "🇨🇱", "智利", ["chile", "cl", "智利"]),
    ("CO", "🇨🇴", "哥伦比亚", ["colombia", "co", "哥伦比亚"]),
    ("PE", "🇵🇪", "秘鲁", ["peru", "pe", "秘鲁"]),
    ("PA", "🇵🇦", "巴拿马", ["panama", "pa", "巴拿马"]),
    ("CR", "🇨🇷", "哥斯达黎加", ["costa rica", "cr", "哥斯达黎加"]),
    ("ZA", "🇿🇦", "南非", ["south africa", "za", "南非"]),
]
REGION_INDEX = {r[0]: (r[1], r[2]) for r in REGION_RULES}


def region_label(code: str) -> tuple[str, str]:
    """地区码 -> (旗帜, 中文名)。节点名和分组名必须用同一套映射,
    否则两者会撞名, 内核报 ProxyGroup 自引用后拒绝整份配置。"""
    return REGION_INDEX.get(code, ("🌐", "未知"))


def detect_region(name: str) -> str:
    """从节点名里猜地区。emoji 旗帜 -> 中文 -> 英文全称 -> 严格词边界的短码。"""
    if not name:
        return "XX"
    low = name.lower()
    # 1. 旗帜 emoji 最可靠
    for code, flag, _cn, _kw in REGION_RULES:
        if flag in name:
            return code
    # 2. 中文关键词
    for code, _flag, cn, _kw in REGION_RULES:
        if cn in name:
            return code
    # 3. 英文/别名, 长词优先; 短码要求独立 token
    scored: list[tuple[int, str]] = []
    for code, _flag, _cn, kws in REGION_RULES:
        for kw in kws:
            if len(kw) <= 3 and kw.isalpha():
                if re.search(rf"(?<![a-z]){re.escape(kw)}(?![a-z])", low):
                    scored.append((len(kw), code))
            elif kw in low:
                scored.append((len(kw) + 10, code))
    if scored:
        scored.sort(reverse=True)
        return scored[0][1]
    return "XX"


# --------------------------------------------------------------------------
# base64 / 链接解析
# --------------------------------------------------------------------------
def b64_fix(s: str) -> str:
    s = re.sub(r"\s+", "", s)
    s = s.replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def b64_decode(s: str) -> str | None:
    try:
        return base64.b64decode(b64_fix(s)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


LINK_RE = re.compile(r"^(vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic)://", re.I)


def qs(q: dict[str, list[str]], key: str, default=None):
    v = q.get(key)
    return v[0] if v else default


def truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "tls", "yes", "on")


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def parse_vmess(link: str) -> dict | None:
    body = link[8:].strip()
    txt = b64_decode(body)
    if not txt:
        return None
    try:
        o = json.loads(txt)
    except json.JSONDecodeError:
        return None
    server = str(o.get("add") or "").strip()
    port = _int(o.get("port"))
    uuid = str(o.get("id") or "").strip()
    if not server or not port or not uuid:
        return None
    p: dict = {
        "name": str(o.get("ps") or "vmess"),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": _int(o.get("aid"), 0),
        "cipher": str(o.get("scy") or "auto") or "auto",
        "udp": True,
    }
    net = str(o.get("net") or "tcp").lower()
    host = str(o.get("host") or "").strip()
    path = str(o.get("path") or "").strip()
    tls = truthy(o.get("tls"))
    sni = str(o.get("sni") or "").strip()
    if tls:
        p["tls"] = True
        if sni:
            p["servername"] = sni
        elif host:
            p["servername"] = host
        if str(o.get("alpn") or "").strip():
            p["alpn"] = [a.strip() for a in str(o["alpn"]).split(",") if a.strip()]
        if truthy(o.get("allowInsecure")) or str(o.get("verify_cert")) == "0":
            p["skip-cert-verify"] = True
        if str(o.get("fp") or "").strip():
            p["client-fingerprint"] = str(o["fp"]).strip()
    if net == "ws":
        p["network"] = "ws"
        opts: dict = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": path or ""}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [h.strip() for h in host.split(",") if h.strip()]
        p["h2-opts"] = opts
    elif net == "tcp" and str(o.get("type") or "").lower() == "http":
        p["network"] = "http"
        opts = {"path": [path or "/"]}
        if host:
            opts["headers"] = {"Host": [h.strip() for h in host.split(",") if h.strip()]}
        p["http-opts"] = opts
    return p


def _url_parts(link: str):
    """返回 (scheme, userinfo, host, port, query, frag)"""
    u = urllib.parse.urlsplit(link)
    return (u.scheme.lower(), urllib.parse.unquote(u.username or ""),
            urllib.parse.unquote(u.password or ""), u.hostname or "", u.port,
            dict(urllib.parse.parse_qs(u.query)), urllib.parse.unquote(u.fragment or ""))


def parse_vless(link: str) -> dict | None:
    scheme, user, _pw, host, port, q, frag = _url_parts(link)
    if not host or not port or not user:
        return None
    p: dict = {"name": frag or "vless", "type": "vless", "server": host,
               "port": port, "uuid": user, "udp": True}
    flow = qs(q, "flow")
    if flow:
        p["flow"] = flow
    sec = (qs(q, "security") or "none").lower()
    sni = qs(q, "sni") or qs(q, "peer")
    net = (qs(q, "type") or "tcp").lower()
    host_hdr = qs(q, "host")
    path = qs(q, "path")
    if sec == "tls":
        p["tls"] = True
        if sni:
            p["servername"] = sni
        elif host_hdr:
            p["servername"] = host_hdr
        if truthy(qs(q, "allowInsecure")):
            p["skip-cert-verify"] = True
        fp = qs(q, "fp")
        if fp:
            p["client-fingerprint"] = fp
        alpn = qs(q, "alpn")
        if alpn:
            p["alpn"] = [a.strip() for a in urllib.parse.unquote(alpn).split(",") if a.strip()]
    elif sec == "reality":
        p["tls"] = True
        p["reality-opts"] = {}
        pbk = qs(q, "pbk")
        if pbk:
            p["reality-opts"]["public-key"] = pbk
        sid = qs(q, "sid")
        if sid:
            p["reality-opts"]["short-id"] = sid
        if sni:
            p["servername"] = sni
        p["client-fingerprint"] = qs(q, "fp") or "chrome"
    if net == "ws":
        p["network"] = "ws"
        opts: dict = {"path": path or "/"}
        if host_hdr:
            opts["headers"] = {"Host": host_hdr}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": qs(q, "serviceName") or path or ""}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        o = {"path": path or "/"}
        if host_hdr:
            o["host"] = [h.strip() for h in host_hdr.split(",") if h.strip()]
        p["h2-opts"] = o
    elif net == "xhttp":
        p["network"] = "xhttp"
        p["xhttp-opts"] = {"path": path or "/"}
        if host_hdr:
            p["xhttp-opts"]["host"] = host_hdr
    return p


def parse_trojan(link: str) -> dict | None:
    scheme, user, _pw, host, port, q, frag = _url_parts(link)
    if not host or not port or not user:
        return None
    p: dict = {"name": frag or "trojan", "type": "trojan", "server": host,
               "port": port, "password": user, "udp": True}
    sni = qs(q, "sni") or qs(q, "peer")
    if sni:
        p["sni"] = sni
    if truthy(qs(q, "allowInsecure")):
        p["skip-cert-verify"] = True
    alpn = qs(q, "alpn")
    if alpn:
        p["alpn"] = [a.strip() for a in urllib.parse.unquote(alpn).split(",") if a.strip()]
    net = (qs(q, "type") or "tcp").lower()
    if net == "ws":
        p["network"] = "ws"
        o = {"path": qs(q, "path") or "/"}
        h = qs(q, "host")
        if h:
            o["headers"] = {"Host": h}
        p["ws-opts"] = o
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": qs(q, "serviceName") or qs(q, "path") or ""}
    return p


def parse_ss(link: str) -> dict | None:
    body = link[5:]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        frag = urllib.parse.unquote(frag)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    method = password = ""
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        dec = b64_decode(userinfo)
        if dec and ":" in dec:
            method, _, password = dec.partition(":")
        elif ":" in urllib.parse.unquote(userinfo):
            method, _, password = urllib.parse.unquote(userinfo).partition(":")
        else:
            return None
    else:
        dec = b64_decode(body)
        if not dec or "@" not in dec:
            return None
        userinfo, hostport = dec.rsplit("@", 1)
        method, _, password = userinfo.partition(":")
    if ":" not in hostport:
        return None
    host, _, port_s = hostport.rpartition(":")
    host = host.strip("[]")
    port = _int(port_s)
    if not host or not port or not method:
        return None
    p: dict = {"name": frag or "ss", "type": "ss", "server": host, "port": port,
               "cipher": method, "password": password, "udp": True}
    if query:
        q = dict(urllib.parse.parse_qs(query))
        plugin = qs(q, "plugin")
        if plugin:
            plugin = urllib.parse.unquote(plugin)
            if plugin.startswith("obfs"):
                opts = dict(kv.split("=", 1) for kv in plugin.split(";")[1:] if "=" in kv)
                p["plugin"] = "obfs"
                p["plugin-opts"] = {"mode": opts.get("obfs", "http"),
                                    "host": opts.get("obfs-host", "")}
            elif plugin.startswith("v2ray-plugin"):
                opts = dict(kv.split("=", 1) for kv in plugin.split(";")[1:] if "=" in kv)
                p["plugin"] = "v2ray-plugin"
                p["plugin-opts"] = {"mode": "websocket",
                                    "host": opts.get("host", ""),
                                    "path": opts.get("path", "/"),
                                    "tls": "tls" in plugin}
    return p


def parse_hysteria2(link: str) -> dict | None:
    scheme, user, pw, host, port, q, frag = _url_parts(link)
    if not host or not port:
        return None
    auth = user or pw
    if not auth:
        return None
    p: dict = {"name": frag or "hysteria2", "type": "hysteria2", "server": host,
               "port": port, "password": auth, "udp": True}
    sni = qs(q, "sni") or qs(q, "peer")
    if sni:
        p["sni"] = sni
    if truthy(qs(q, "insecure")) or truthy(qs(q, "allowInsecure")):
        p["skip-cert-verify"] = True
    obfs = qs(q, "obfs")
    if obfs and obfs != "none":
        p["obfs"] = obfs
        p["obfs-password"] = qs(q, "obfs-password") or qs(q, "obfsParam") or ""
    return p


def parse_tuic(link: str) -> dict | None:
    scheme, user, pw, host, port, q, frag = _url_parts(link)
    if not host or not port or not user:
        return None
    p: dict = {"name": frag or "tuic", "type": "tuic", "server": host, "port": port,
               "uuid": user, "password": pw or "", "udp": True}
    sni = qs(q, "sni")
    if sni:
        p["sni"] = sni
    if truthy(qs(q, "allow_insecure")) or truthy(qs(q, "insecure")):
        p["skip-cert-verify"] = True
    alpn = qs(q, "alpn")
    if alpn:
        p["alpn"] = [a.strip() for a in urllib.parse.unquote(alpn).split(",") if a.strip()]
    cc = qs(q, "congestion_control") or qs(q, "congestion")
    if cc:
        p["congestion-controller"] = cc
    return p


PARSERS = {
    "vmess": parse_vmess, "vless": parse_vless, "trojan": parse_trojan,
    "ss": parse_ss, "hysteria2": parse_hysteria2, "hy2": parse_hysteria2,
    "hysteria": parse_hysteria2, "tuic": parse_tuic,
}


def parse_links(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINK_RE.match(line)
        if not m:
            continue
        fn = PARSERS.get(m.group(1).lower())
        if not fn:
            continue
        try:
            p = fn(line)
        except Exception:
            p = None
        if p:
            out.append(p)
    return out


# --------------------------------------------------------------------------
# Clash YAML 读取 (PyYAML 优先, 缺失则用内置子集解析器)
# --------------------------------------------------------------------------
try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def _mini_yaml_proxies(text: str) -> list[dict]:
    """内置降级解析器: 只认 Clash 的 proxies 列表块 (缩进式), 足够覆盖订阅场景。"""
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*proxies\s*:\s*$", ln):
            start = i + 1
            break
    if start is None:
        return []
    base_indent = None
    items: list[dict] = []
    cur: dict | None = None
    stack: list[tuple[int, dict]] = []

    def scalar(v: str):
        v = v.strip()
        if v in ("", "~", "null"):
            return None
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            return v[1:-1]
        if v.lower() in ("true", "yes"):
            return True
        if v.lower() in ("false", "no"):
            return False
        if re.fullmatch(r"-?\d+", v):
            return int(v)
        if v.startswith("[") and v.endswith("]"):
            return [scalar(x) for x in v[1:-1].split(",") if x.strip()]
        return v

    for ln in lines[start:]:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if re.match(r"^\s*(proxy-groups|rules|dns|tun)\s*:", ln):
            break
        indent = len(ln) - len(ln.lstrip())
        body = ln.strip()
        if body.startswith("- ") or body == "-":
            base_indent = indent if base_indent is None else base_indent
            if indent != base_indent:
                continue
            cur = {}
            items.append(cur)
            stack = [(base_indent, cur)]
            rest = body[2:].strip()
            if rest and ":" in rest:
                k, _, v = rest.partition(":")
                cur[k.strip()] = scalar(v)
            continue
        if cur is None:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            continue
        parent = stack[-1][1]
        if ":" not in body:
            continue
        k, _, v = body.partition(":")
        k = k.strip()
        v = v.strip()
        if v == "":
            child: dict = {}
            parent[k] = child
            stack.append((indent, child))
        else:
            parent[k] = scalar(v)
    return [p for p in items if isinstance(p.get("server"), str) and p.get("port")]


def parse_clash_yaml(text: str) -> list[dict]:
    if _yaml is not None:
        try:
            data = _yaml.safe_load(text)
            if isinstance(data, dict):
                px = data.get("proxies")
                if isinstance(px, list):
                    return [p for p in px if isinstance(p, dict) and p.get("server")]
                for key in ("proxy-providers", "proxyProvider"):
                    pass
            return []
        except Exception:
            pass
    return _mini_yaml_proxies(text)


# --------------------------------------------------------------------------
# 归一 / 清洗 / 去重
# --------------------------------------------------------------------------
AD_PAT = re.compile(
    r"(?:t\.me/|telegram|https?://|@[a-z0-9_]{3,}|\|?\s*(?:tg|电报)?\s*(?:频道|群组|群|订阅|节点分享|免费节点|公益|机场推荐))",
    re.I)


def clean_name(raw: str) -> str:
    # 必须先截断再跑正则。AD_PAT 的匹配是超线性的(实测 4000 字节要 119 秒,
    # 每翻倍约 ×8), 而原来的 n[:38] 截断在正则之后 —— 长度上限形同不存在,
    # 一条 32KB 的恶意节点名能把整轮刷新挂住十几小时。这是一行修复。
    n = re.sub(r"[\r\n\t]+", " ", str(raw or ""))[:120]
    n = AD_PAT.sub(" ", n)
    n = re.sub(r"[\[\]【】()（）]", " ", n)
    n = re.sub(r"[\U0001F1E6-\U0001F1FF]{2}", " ", n)  # 先剥旗帜, 稍后按地区补
    n = re.sub(r"\s+", " ", n).strip(" -_|·,.")
    return n[:38]


VALID_TYPES = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic", "anytls"}

# 每种协议允许保留的字段。其余一律丢弃。
#
# 之前是"黑名单剔掉几个键、剩下全量透传", 后果是攻击者能往节点里塞内核级字段
# 并被内核照单全收 —— 实测 udp/smux 生效、dialer-proxy 能改拨号链、
# interface-name 能指定出站网卡、tun 能塞进 proxies[]。这些不突破"只绑回环 /
# 禁 tun"的顶层边界, 但等于把 harden_kernel_config 绕过去了一半。
_COMMON_KEYS = {
    "name", "type", "server", "port", "udp", "tfo", "mptcp", "ip-version",
    "skip-cert-verify", "client-fingerprint", "alpn", "servername", "sni",
}
_TYPE_KEYS = {
    "vmess": {"uuid", "alterId", "cipher", "tls", "network",
              "ws-opts", "grpc-opts", "h2-opts", "http-opts"},
    "vless": {"uuid", "flow", "tls", "network", "reality-opts",
              "ws-opts", "grpc-opts", "h2-opts", "xhttp-opts"},
    "trojan": {"password", "network", "ws-opts", "grpc-opts"},
    "ss": {"cipher", "password", "plugin", "plugin-opts"},
    "ssr": {"cipher", "password", "protocol", "protocol-param", "obfs", "obfs-param"},
    "hysteria": {"auth-str", "auth", "obfs", "protocol", "up", "down",
                 "ports", "fingerprint", "recv-window", "ca-str"},
    "hysteria2": {"password", "obfs", "obfs-password", "up", "down",
                  "ports", "fingerprint", "ca-str"},
    "tuic": {"uuid", "password", "congestion-controller", "udp-relay-mode",
             "reduce-rtt", "heartbeat-interval", "request-timeout"},
    "anytls": {"password", "idle-session-check-interval", "idle-session-timeout",
               "min-idle-session"},
}
# 嵌套选项同样要白名单 —— 攻击者可以往 ws-opts / headers 里塞任意东西
_OPTS_KEYS = {
    "ws-opts": {"path", "headers", "max-early-data", "early-data-header-name",
                "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"},
    "grpc-opts": {"grpc-service-name"},
    "h2-opts": {"host", "path"},
    "http-opts": {"method", "path", "headers"},
    "xhttp-opts": {"path", "host", "mode"},
    "reality-opts": {"public-key", "short-id"},
    "plugin-opts": {"mode", "host", "path", "tls"},
}


def _norm_key(k) -> str:
    """键名归一(用于**匹配**): 小写 + 下划线转横线。

    内核的解码器对键名不区分大小写, 还会把下划线当横线 —— 所以
    `Skip-Cert-Verify` / `skip_cert_verify` 在内核眼里都等于
    `skip-cert-verify`(实测 `SKIP-CERT-VERIFY: "abc"` 让内核报出
    `'skip-cert-verify' expected type 'bool'`)。不归一的话, 攻击者用变体写法
    就能既绕过白名单、又绕过布尔归一的审计告警。
    """
    return str(k).strip().lower().replace("_", "-")


# 归一只用于匹配; 写进配置时必须还原成内核认的规范写法。
# `alterId` 是 camelCase, 归一成 `alterid` 之后内核直接拒绝:
# "proxy 0: '' has unset fields: alterId"(实测)。其余字段本身都是小写横线形式。
_CANON_KEYS = {
    "alterid": "alterId",
}


def _filter_keys(p: dict, t: str) -> dict:
    """按协议类型白名单过滤字段。`_` 前缀的内部字段原样保留。"""
    allowed = ({_norm_key(x) for x in _COMMON_KEYS}
               | {_norm_key(x) for x in _TYPE_KEYS.get(t, set())})
    out: dict = {}
    for k, v in p.items():
        if str(k).startswith("_"):
            out[k] = v
            continue
        nk = _norm_key(k)
        if nk in allowed:
            out[_CANON_KEYS.get(nk, nk)] = v
    for opt, ok in _OPTS_KEYS.items():
        d = out.get(opt)
        if isinstance(d, dict):
            ok_norm = {_norm_key(x) for x in ok}
            kept = {}
            for k, v in d.items():
                nk = _norm_key(k)
                if nk in ok_norm:
                    kept[_CANON_KEYS.get(nk, nk)] = v
            if kept:
                out[opt] = kept
            else:
                out.pop(opt, None)
    return out


def _normalize_bools(p: dict):
    """把布尔字段归一成真 bool。

    内核用 structure 解码器, `udp: 1` 与 `udp: true` 等价(实测 /proxies 里
    `udp: 1` 被读成 true), 而审计代码里写的是 `is True` ——
    于是 `skip-cert-verify: 1` / `Skip-Cert-Verify: true` 这类变体写法能骗过
    审计。统一成真布尔之后审计才真正生效。
    """
    for k in ("tls", "udp", "skip-cert-verify", "tfo", "mptcp",
              "reduce-rtt", "v2ray-http-upgrade"):
        if k not in p:
            continue
        v = p[k]
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            p[k] = bool(v)
        elif isinstance(v, str):
            p[k] = v.strip().lower() in ("1", "true", "yes", "on")
        else:
            p.pop(k, None)

# YAML 禁止的字符, 一个都不能漏:
#   \x00-\x1f  C0 控制符
#   \x7f-\x9f  DEL + C1 控制符(之前只清了 \x85, 漏掉 \x80-\x9f 其余部分,
#              结果 600 个节点的配置报 "yaml: control characters are not allowed",
#              而 prune 靠 "proxy N:" 定位坏节点, 这个错误没有索引 —— 整片被丢)
#   \u2028\u2029  Unicode 行分隔符(会被当换行, 可用于键名逃逸)
#   \ufffe\uffff 非字符
_CTRL_RE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\ufffe\uffff]")


def scrub(v, depth: int = 0):
    """递归剔除字符串里的控制字符与 Unicode 行分隔符。

    公开免费源里混着畸形数据(被截断的 base64、带 %00 的 URL 编码),
    这些字符会让 YAML 解析器直接报 "control characters are not allowed" ——
    一个坏节点就能让整份配置作废, 内核拒绝启动。

    U+0085 / U+2028 / U+2029 必须一起清: 它们不在 \\x00-\\x1f 里, 但 YAML
    读取端把它们当换行, 藏在键名里就能往产物顶层注入任意键(实测可注入 tun,
    绕过 harden_kernel_config)。见 security.LINE_SEP_CHARS。

    深度上限防的是深嵌套输入把递归撑爆 —— 约 600KB 的源就能造出 1100 层,
    直接把整轮刷新打成 RecursionError。
    """
    if depth > 32:
        return "" if isinstance(v, str) else v
    if isinstance(v, str):
        return _CTRL_RE.sub("", v)
    if isinstance(v, dict):
        return {scrub(k, depth + 1): scrub(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x, depth + 1) for x in v]
    return v


def normalize(p: dict) -> dict | None:
    t = str(p.get("type") or "").lower()
    if t == "hy2":
        t = "hysteria2"
    if t not in VALID_TYPES:
        return None
    server = str(p.get("server") or "").strip()
    port = _int(p.get("port"))
    if not server or not (0 < port < 65536):
        return None
    if server.startswith("[") and server.endswith("]"):
        server = server[1:-1]
    if bad_server(server):
        return None
    out = dict(p)
    out["type"] = t
    out["server"] = server
    out["port"] = port
    # 丢弃内核不认的杂项
    for junk in ("id", "aid", "ps", "add", "scy", "v", "host", "path", "tls_sni"):
        out.pop(junk, None)
    out = _filter_keys(out, t)
    _normalize_bools(out)
    # 补必需字段的默认值。内核对这些字段是"必须存在", 不是"有默认" ——
    # 实测缺 alterId 的 vmess 节点会被直接拒绝:
    #   proxy 5: '' has unset fields: alterId
    # 而很多 Clash 源确实不写这个字段, 不补的话这类节点会被整片判死。
    if t == "vmess":
        out.setdefault("alterId", 0)
        out.setdefault("cipher", "auto")
    if bad_credential(out):
        return None
    raw_name = str(p.get("name") or "")
    region = detect_region(raw_name + " " + server)
    if region == "CN":
        return None  # 国内节点, 不是翻墙节点
    flag, cn = REGION_INDEX.get(region, ("🌐", "未知"))
    base = clean_name(raw_name)
    if base.lower() in GENERIC_NAMES:
        base = ""
    if base:
        out["name"] = f"{flag} {base}"
    else:
        # 名字清洗后为空时不能只留地区名 —— 那会和地区分组同名,
        # 内核会报 "loop is detected in ProxyGroup" 并拒绝整份配置。
        # 带上服务器片段既能区分同名节点, 也天然避开分组名。
        out["name"] = f"{flag} {cn} · {server[:18]}"
    out["_region"] = region
    out["_raw_name"] = raw_name
    return scrub(out)


def fingerprint(p: dict) -> str:
    key = "|".join(str(x) for x in (
        p.get("type"), p.get("server", "").lower(), p.get("port"),
        p.get("uuid") or p.get("password") or "",
        p.get("network") or "", p.get("servername") or p.get("sni") or "",
        json.dumps(p.get("ws-opts") or {}, sort_keys=True),
        p.get("grpc-opts", {}).get("grpc-service-name") if isinstance(p.get("grpc-opts"), dict) else "",
        p.get("reality-opts", {}).get("public-key") if isinstance(p.get("reality-opts"), dict) else "",
    ))
    return hashlib.md5(key.encode("utf-8")).hexdigest()


# 无信息量的名字, 用地区名替代
GENERIC_NAMES = {
    "vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hysteria2", "hy2", "tuic",
    "anytls", "node", "nodes", "proxy", "proxies", "free", "unknown", "none", "config",
}
FAKE_UUIDS = {
    "88888888-8888-8888-8888-888888888888",
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
}

# 内核只认这些加密方式, 其余一律让 mihomo 拒绝启动 ("unknown method")。
# 免费源里 ss 节点的 cipher 字段经常是乱码, 必须白名单校验。
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb1", "aes-192-cfb1", "aes-256-cfb1",
    "aes-128-cfb8", "aes-192-cfb8", "aes-256-cfb8",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20", "chacha20-ietf", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "rc4-md5", "rc4-md5-6",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "sm4-gcm", "sm4-cbc", "none", "dummy",
}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$", re.I)


def bad_server(host: str) -> bool:
    """回环 / 内网 / 保留 IP 一律丢弃。

    免费源里存在故意投放的诱饵节点(如 127.0.0.53 的"防范境外势力渗透"),
    这类地址 TCP 能连通本机, 会骗过 L1 探活污染池子。
    """
    h = (host or "").strip().strip("[]").lower()
    if not h or h in ("localhost", "::1", "0.0.0.0"):
        return True
    if h.endswith((".local", ".lan", ".internal", ".localhost", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False  # 域名, 放行
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def bad_host(h: str) -> bool:
    """域名/IP 合法性。乱码主机名同样会让内核拒绝启动。"""
    h = (h or "").strip()
    if not h or len(h) > 253:
        return True
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    return not _HOST_RE.match(h)


def bad_credential(p: dict) -> bool:
    t = p["type"]
    if bad_host(p.get("server")):
        return True
    if t in ("vmess", "vless"):
        u = str(p.get("uuid") or "").strip()
        if not u or u.lower() in FAKE_UUIDS:
            return True
        # 宽松校验: 只挡乱码, 不强制标准 UUID 格式(部分 vless 用自定义 ID)
        if not re.fullmatch(r"[0-9a-fA-F\-]{16,48}", u):
            return True
        if re.fullmatch(r"(.)\1{7,}", u.replace("-", "")):
            return True
    elif t in ("trojan", "hysteria2", "hy2", "tuic", "anytls"):
        if not str(p.get("password") or "").strip():
            return True
    if t == "tuic":
        # tuic 的 uuid 会被直接拼进通用订阅链接, 含 # / @ 之类的字符会把
        # 链接结构撑破, 污染客户端的订阅
        u = str(p.get("uuid") or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F\-]{16,48}", u):
            return True
    if t == "ss":
        if not str(p.get("password") or "").strip():
            return True
        if str(p.get("cipher") or "").lower() not in SS_CIPHERS:
            return True
    elif t == "vmess":
        if str(p.get("cipher") or "auto").lower() not in VMESS_CIPHERS:
            return True
    return False


# --------------------------------------------------------------------------
# 反向生成链接 (给通用订阅用)
# --------------------------------------------------------------------------
def proxy_to_link(p: dict) -> str | None:
    t = p["type"]
    name = urllib.parse.quote(str(p.get("name") or ""), safe="")
    net = p.get("network") or "tcp"
    tls = bool(p.get("tls"))
    sni = p.get("servername") or p.get("sni") or ""
    if t == "vmess":
        o = {
            "v": "2", "ps": p.get("name", ""), "add": p["server"], "port": str(p["port"]),
            "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
            "scy": p.get("cipher", "auto"), "net": net, "type": "none",
            "host": "", "path": "", "tls": "tls" if tls else "",
            "sni": sni, "alpn": ",".join(p.get("alpn") or []),
        }
        if net == "ws":
            w = p.get("ws-opts") or {}
            o["path"] = w.get("path", "/")
            o["host"] = (w.get("headers") or {}).get("Host", "")
        elif net == "grpc":
            o["path"] = (p.get("grpc-opts") or {}).get("grpc-service-name", "")
        elif net == "h2":
            h = p.get("h2-opts") or {}
            o["path"] = h.get("path", "/")
            o["host"] = ",".join(h.get("host") or [])
        return "vmess://" + b64_encode(json.dumps(o, ensure_ascii=False, separators=(",", ":")))
    if t == "vless":
        q: dict[str, str] = {"encryption": "none", "type": net}
        if tls:
            if p.get("reality-opts"):
                q["security"] = "reality"
                q["pbk"] = p["reality-opts"].get("public-key", "")
                if p["reality-opts"].get("short-id"):
                    q["sid"] = p["reality-opts"]["short-id"]
            else:
                q["security"] = "tls"
            if sni:
                q["sni"] = sni
            if p.get("client-fingerprint"):
                q["fp"] = p["client-fingerprint"]
        if p.get("flow"):
            q["flow"] = p["flow"]
        if net == "ws":
            w = p.get("ws-opts") or {}
            q["path"] = w.get("path", "/")
            h = (w.get("headers") or {}).get("Host")
            if h:
                q["host"] = h
        elif net == "grpc":
            q["serviceName"] = (p.get("grpc-opts") or {}).get("grpc-service-name", "")
        return f"vless://{p.get('uuid','')}@{p['server']}:{p['port']}?{urllib.parse.urlencode(q)}#{name}"
    if t == "trojan":
        q = {"type": net}
        if sni:
            q["sni"] = sni
        if net == "ws":
            w = p.get("ws-opts") or {}
            q["path"] = w.get("path", "/")
            h = (w.get("headers") or {}).get("Host")
            if h:
                q["host"] = h
        return (f"trojan://{urllib.parse.quote(str(p.get('password','')), safe='')}"
                f"@{p['server']}:{p['port']}?{urllib.parse.urlencode(q)}#{name}")
    if t == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{p.get('cipher','')}:{p.get('password','')}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{p['server']}:{p['port']}#{name}"
    if t in ("hysteria2", "hy2"):
        q = {}
        if sni:
            q["sni"] = sni
        if p.get("skip-cert-verify"):
            q["insecure"] = "1"
        if p.get("obfs"):
            q["obfs"] = p["obfs"]
            q["obfs-password"] = p.get("obfs-password", "")
        return (f"hysteria2://{urllib.parse.quote(str(p.get('password','')), safe='')}"
                f"@{p['server']}:{p['port']}?{urllib.parse.urlencode(q)}#{name}")
    if t == "tuic":
        q = {}
        if sni:
            q["sni"] = sni
        if p.get("alpn"):
            q["alpn"] = ",".join(p["alpn"])
        return (f"tuic://{p.get('uuid','')}:{urllib.parse.quote(str(p.get('password','')), safe='')}"
                f"@{p['server']}:{p['port']}?{urllib.parse.urlencode(q)}#{name}")
    return None


# --------------------------------------------------------------------------
# 拉源
# --------------------------------------------------------------------------
def load_sources() -> list[str]:
    if not SOURCES.exists():
        return []
    out = []
    for ln in SOURCES.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


MIRRORS = ("https://ghfast.top/", "https://gh-proxy.com/", "https://ghproxy.net/")
_GH_HOSTS = ("https://raw.githubusercontent.com/", "https://github.com/",
             "https://gist.githubusercontent.com/")


def mirror_urls(url: str) -> list[str]:
    """GitHub 直连在国内经常被掐, 依次回退到公共镜像。"""
    if not url.startswith(_GH_HOSTS):
        return [url]
    return [url] + [m + url for m in MIRRORS]


_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http_get(u: str, timeout: int, use_proxy: bool) -> bytes | None:
    req = urllib.request.Request(u, headers={
        "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity",
    })
    opener = None if use_proxy else _NO_PROXY_OPENER
    if opener is None:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(sec.MAX_RESPONSE_BYTES + 1)
    with opener.open(req, timeout=timeout) as r:
        return r.read(sec.MAX_RESPONSE_BYTES + 1)


def fetch_one(url: str, timeout: int = 25, retries: int = 2) -> tuple[str, str | None]:
    """直连优先, 失败回退镜像。镜像超时收紧, 免得一个死源拖住整轮。

    **每条 URL 都试两种走法: 走系统代理 / 绕开代理。**

    为什么必须这样: 本机开着系统代理(Clash Verge 的 127.0.0.1:7897),
    而 urllib 默认读系统代理 —— 代理的节点一死, **连本来能用的镜像站
    也一起拉不到**。实测同一个镜像:
        走代理   → SSL: UNEXPECTED_EOF_WHILE_READING
        绕开代理 → 200 OK
    而裸的 raw.githubusercontent.com 恰恰相反(直连被墙, 必须走代理)。
    所以两种走法都要试, 谁通用谁。

    这是个先有鸡还是先有蛋的问题: 拉节点要经过 VPN, 而 VPN 的节点
    正是我们在找的东西。所以不能假设代理一定是好的。

    **全部失败后还会重试。** 16 个线程并发拉源时偶发失败是常态 ——
    实测最值钱的那个源(单源贡献过半可用节点)在批量里会拉取失败,
    单独测却秒回 230KB。没有重试的话池子规模就在"有它"和"没它"之间
    反复横跳(实测同一天里 8 个 vs 95 个节点)。

    响应体按 sec.MAX_RESPONSE_BYTES 硬截断 —— 源是不可信输入,
    不能让它用超大响应把内存打爆。
    """
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(0.7 * attempt)     # 退避, 别和别的线程一起重试
        for i, u in enumerate(mirror_urls(url)):
            t = timeout if i == 0 else max(12, timeout - 8)
            for use_proxy in (True, False):
                try:
                    data = _http_get(u, t, use_proxy)
                except Exception:
                    continue
                if not data:
                    continue
                if len(data) > sec.MAX_RESPONSE_BYTES:
                    print(f"      [安全] 响应超过 {sec.MAX_RESPONSE_BYTES // 1048576}MB, 丢弃该源")
                    continue
                return url, data.decode("utf-8", "replace")
    return url, None


def parse_any(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    head = text[:6000]
    if "proxies:" in head or re.match(r"^\s*(mixed-port|port|socks-port|proxy-groups|proxies)\s*:", head):
        got = parse_clash_yaml(text)
        if got:
            return got
    if LINK_RE.search(text):
        return parse_links(text)
    dec = b64_decode(text)
    if dec and "://" in dec:
        if not LINK_RE.search(dec):
            d2 = b64_decode(dec)
            if d2 and "://" in d2:
                dec = d2
        return parse_links(dec)
    got = parse_clash_yaml(text)
    if got:
        return got
    return parse_links(text)


def collect(verbose: bool = True) -> tuple[list[dict], dict]:
    urls = load_sources()
    if not urls:
        print("[!] sources.txt 里没有源")
        return [], {}
    RAW.mkdir(parents=True, exist_ok=True)
    stats: dict[str, dict] = {}
    pool: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(fetch_one, u): u for u in urls}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            url, text = fut.result()
            tag = f"src{i:02d}"
            if text is None:
                stats[url] = {"ok": False, "n": 0}
                if verbose:
                    print(f"  [{tag}] 拉取失败  {url[:78]}")
                continue
            if sec.yaml_bomb(text):
                stats[url] = {"ok": False, "n": 0, "blocked": "yaml-bomb"}
                if verbose:
                    print(f"  [{tag}] [安全] YAML 锚点炸弹或超长文本, 整源丢弃  {url[:58]}")
                continue
            text = sec.clamp_text(text)
            try:
                raw_nodes = parse_any(text)
            except Exception as e:
                raw_nodes = []
                if verbose:
                    print(f"  [{tag}] 解析异常 {type(e).__name__}  {url[:60]}")
            capped = raw_nodes[:PER_SOURCE_CAP]
            stats[url] = {"ok": True, "n": len(capped), "bytes": len(text)}
            pool.extend(capped)
            if verbose:
                print(f"  [{tag}] {len(capped):>5} 节点  ({len(text)//1024:>4}KB)  {url[:70]}")
    return pool, stats


def dedupe(raw: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    bad = 0
    for p in raw:
        # 单个畸形节点不该毁掉整轮刷新。实测深嵌套输入能让 normalize → scrub
        # 爆栈抛 RecursionError, 而 dedupe / run_cycle 之前都没有兜底,
        # 结果是 daemon 每轮都失败。
        try:
            n = normalize(p)
        except Exception:
            bad += 1
            continue
        if not n:
            continue
        fp = fingerprint(n)
        if fp in seen:
            continue
        seen.add(fp)
        n["_fp"] = fp
        out.append(n)
    if bad:
        print(f"[!] {bad} 个节点在归一阶段异常, 已跳过")
    return out


# --------------------------------------------------------------------------
# L1: TCP 探活
# --------------------------------------------------------------------------
# QUIC(UDP) 协议**不监听 TCP** —— L1 的 TCP 三次握手对它们必然失败, 不是网络
# 问题, 是探错了东西。实测(某轮 Ruk1ng001 的 76 个节点, 全部同时送 L1 和 L2):
#
#     协议         总数   L1存活   L2可用   被L1误杀   L1通过率
#     vless        23     17      4        0        74%
#     vmess        11      9      3        0        82%
#     anytls        9      9      4        0       100%
#     ss            8      4      4        0        50%
#     trojan        8      6      1        0        75%
#     hysteria2    13      2      5        3        15%
#     hysteria      2      0      2        2         0%
#     tuic          2      0      1        1         0%
#
# 被误杀的 6 个**全是** QUIC 协议: 它们的 TCP 直连是 Timeout/ConnectionRefused,
# 把 L1 超时放大到 15s 也没用(不是超时问题), 而 getaddrinfo 一切正常 ——
# 所以这跟"Python 的 DNS 解析路径"无关。TCP 协议那侧 L1 通过率 50%~100%,
# 误杀 0 个, 说明 L1 对它们是对的。
#
# 结论: 这些协议**跳过 L1 直接送 L2**, L1 只负责筛 TCP 节点。代价是 L2 候选
# 变多(实测这一轮多 22%), 由 l2_top 与 L2 负缓存兜住。
UDP_TYPES = frozenset({"hysteria", "hysteria2", "hy2", "tuic"})

# 标记: 该节点没做 TCP 探测, 是被 L1 放行进来的
L1_SKIP_UDP = "udp"


def is_udp_type(node: dict) -> bool:
    return str(node.get("type") or "").strip().lower() in UDP_TYPES


async def _tcp_once(host: str, port: int, timeout: float):
    """返回 (延迟ms, 是否超时)。

    区分"超时"和"其它失败"是为了省掉无谓的重试: 超时说明这个节点根本不响应,
    重试一次只是再等一个完整 timeout。L1 里死节点占六成, 这个差别是几十秒。
    """
    t0 = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout)
        # 连上之后看**实际连到哪个 IP** —— 这是挡 DNS 重绑定的唯一可靠办法。
        # `127.0.0.1.nip.io` / `127-0-0-1.sslip.io` 这类域名解析出来就是回环,
        # "服务器是不是字面量内网地址"的检查挡不住, 但 peer 地址骗不了人。
        # 实测这类节点零告警通过审计, 内核解析后真的连上了本机监听端口。
        try:
            peer = writer.get_extra_info("peername")
            if peer and peer[0]:
                addr = ipaddress.ip_address(peer[0])
                if (addr.is_loopback or addr.is_private or addr.is_link_local
                        or addr.is_reserved or addr.is_unspecified):
                    writer.close()
                    return None, False
        except (ValueError, TypeError, IndexError):
            pass
        dt = (time.perf_counter() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return dt, False
    except (asyncio.TimeoutError, TimeoutError):
        return None, True
    except Exception:
        return None, False


async def _tcp_probe(p: dict, sem: asyncio.Semaphore, timeout: float, tries: int):
    best = None
    async with sem:
        for _ in range(tries):
            dt, timed_out = await _tcp_once(p["server"], p["port"], timeout)
            if dt is not None:
                best = dt if best is None else min(best, dt)
            if timed_out:
                break  # 超时的不用重试
    return p, best


def probe_tcp(nodes: list[dict], timeout: float = 3.0, concurrency: int = 300,
              tries: int = 2, hist: dict | None = None,
              ttl: int = 5400, min_fails: int = 2,
              op: str = "扫描") -> list[dict]:
    """L1 TCP 探活。

    带**负缓存**: 连续失败 >= min_fails 次且最后一次在 ttl 秒内的节点直接跳过。
    理由是算过账的 —— 一轮要探 1 万个候选, 其中七成是死的, 每个白等满超时;
    而免费源里相当一部分节点是"长期死的", 每轮重复探它们纯属浪费。
    连续失败两次才跳, 且 ttl 到期自动重探, 所以偶尔抽风的节点不会被永久拉黑。

    过程中会定期回报进度 —— 一轮要跑 90 秒, 之前只在结束时打一行,
    界面上那 90 秒完全是黑的。

    QUIC(hysteria/tuic)节点不参与 TCP 探测, 直接放行(见 UDP_TYPES 的说明)。
    """
    now = time.time()
    # 先把 QUIC 协议挑出来: 它们不监听 TCP, 探测必然失败, 只能交给 L2 判。
    udp = [n for n in nodes if is_udp_type(n)]
    for n in udp:
        n["_l1_skip"] = L1_SKIP_UDP
    tcp_nodes = [n for n in nodes if not is_udp_type(n)]
    todo, skip = _negcache_filter(tcp_nodes, hist or {}, ttl, min_fails)
    total = len(todo)
    done = 0
    stop = False
    sem: asyncio.Semaphore | None = None

    async def one(n):
        nonlocal done
        r = await _tcp_probe(n, sem, timeout, tries)
        done += 1
        return r

    async def ticker():
        last_print = 0.0
        while not stop:
            await asyncio.sleep(1.0)
            set_progress(op, "L1 TCP 探活", done, total)
            # 每 10 秒在日志里留一行, 免得 90 秒里一个字都没有
            if time.time() - last_print >= 10:
                last_print = time.time()
                print(f"[L1] 探活中 {done}/{total} …", flush=True)

    async def run():
        nonlocal stop, sem
        sem = asyncio.Semaphore(concurrency)
        tk = asyncio.create_task(ticker())
        try:
            return await asyncio.gather(*[one(n) for n in todo])
        finally:
            stop = True
            tk.cancel()

    t0 = time.time()
    set_progress(op, "L1 TCP 探活", 0, total)
    results = asyncio.run(run()) if todo else []
    # 放行的 QUIC 节点排在最前, 后面的 TCP 节点按探测结果追加 —— rank() 会重排
    alive = list(udp)
    for p, dt in results:
        if dt is not None:
            p["_tcp"] = round(dt, 1)
            alive.append(p)
    if hist is not None:
        _negcache_record(hist, [(p, dt is not None) for p, dt in results])
    extra = f", 负缓存跳过 {skip} 个" if skip else ""
    udp_note = f", {len(udp)} 个 QUIC 节点跳过 TCP 探测(直接送 L2)" if udp else ""
    print(f"[L1] TCP 探活: {len(alive)}/{len(nodes)} 存活  "
          f"({time.time()-t0:.1f}s, 并发 {concurrency}{extra}{udp_note})")
    return alive


# --------------------------------------------------------------------------
# L2: mihomo 真实测速
# --------------------------------------------------------------------------
class Kernel:
    """mihomo 内核的一个实例。

    每次实例化都随机生成控制端口与密钥。这不是洁癖 —— mihomo 的 REST API
    会回 `Access-Control-Allow-Origin: *`, 并在 preflight 里放行
    `Authorization` 头和 `PATCH` 方法, 这两个行为在 pool.py 侧关不掉。
    密钥写死的话, 用户浏览器里打开的**任意网页**就能在探测窗口期内执行
    `PATCH /configs {"allow-lan":true,"bind-address":"0.0.0.0"}`, 把本机代理
    端口开成局域网开放代理(实测返回 204, 监听从 127.0.0.1:17890 变成
    0.0.0.0:17890 + [::]:17890), 直接推翻 harden_kernel_config 的收口。
    端口和密钥都随机之后, 网页既猜不到端口也猜不到密钥。
    """

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.secret = secrets.token_urlsafe(24)
        self.port = random.randint(20000, 60000)

    @property
    def ctrl(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def api(self, path: str, timeout: float = 10.0):
        req = urllib.request.Request(
            self.ctrl + path,
            headers={"Authorization": f"Bearer {self.secret}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def delay(self, name: str, timeout_ms: int = 3000,
              test_url: str = TEST_URL) -> int | None:
        q = urllib.parse.urlencode({"timeout": timeout_ms, "url": test_url})
        try:
            d = self.api(f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}",
                         timeout=timeout_ms / 1000 + 6)
            v = d.get("delay")
            return int(v) if v else None
        except Exception:
            return None

    def write_config(self, nodes: list[dict]) -> Path:
        KERNEL_DIR.mkdir(parents=True, exist_ok=True)
        proxies = []
        for i, n in enumerate(nodes):
            q = {k: v for k, v in n.items() if not k.startswith("_")}
            q["name"] = f"n{i:05d}"
            proxies.append(q)
        cfg = {
            "mixed-port": 17890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "silent",
            "ipv6": False,
            "unified-delay": True,
            "tcp-concurrent": True,
            "find-process-mode": "off",
            "profile": {"store-selected": False, "store-fake-ip": False},
            "proxies": proxies,
            "rules": ["MATCH,DIRECT"],
        }
        # 内核加载的是不可信节点配置, 统一收口:
        # 禁 tun / 禁 GEO 下载 / 控制端口只绑回环 + 随机密钥
        cfg = sec.harden_kernel_config(cfg, self.secret)
        cfg["external-controller"] = f"127.0.0.1:{self.port}"
        path = KERNEL_DIR / "config.yaml"
        path.write_text(_dump_yaml(cfg), encoding="utf-8")
        return path

    def check(self, cfg: Path) -> int | None:
        """跑 mihomo -t 校验配置。通过返回 None, 否则返回首个坏节点索引 (-1=定位不到)。"""
        try:
            r = subprocess.run(
                [str(MIHOMO), "-d", str(KERNEL_DIR), "-f", str(cfg), "-t"],
                capture_output=True, text=True, timeout=90,
                encoding="utf-8", errors="replace",
                cwd=str(KERNEL_DIR), env=sec.kernel_env(),
                creationflags=sec.kernel_creationflags(),
                preexec_fn=sec.kernel_preexec(),
            )
        except (subprocess.TimeoutExpired, OSError):
            return -1
        if r.returncode == 0:
            return None
        m = re.search(r"proxy (\d+):", (r.stderr or "") + (r.stdout or ""))
        return int(m.group(1)) if m else -1

    def prune(self, nodes: list[dict], max_rounds: int = 16, _depth: int = 0) -> list[dict]:
        """内核遇到坏节点就 fail-fast 只报一个, 所以循环剔除直到配置被接受。

        静态校验已挡掉绝大多数脏数据, 这里兜住长尾 —— 一个坏节点会让整批
        节点的 L2 测速全部报废。

        有些错误(比如 "yaml: control characters are not allowed")不带
        `proxy N:` 索引, 定位不到具体是哪个节点。这种情况**不能整片丢掉**:
        二分再试, 把范围缩到能定位为止, 好节点一个都不损失。
        """
        dropped = 0
        for _ in range(max_rounds):
            bad = self.check(self.write_config(nodes))
            if bad is None:
                if dropped:
                    print(f"[L2] 剔除 {dropped} 个内核不接受的节点后配置通过")
                return nodes
            if bad < 0 or bad >= len(nodes):
                if len(nodes) > 1 and _depth < 8:
                    mid = len(nodes) // 2
                    left = self.prune(nodes[:mid], max_rounds=4, _depth=_depth + 1)
                    right = self.prune(nodes[mid:], max_rounds=4, _depth=_depth + 1)
                    return left + right
                print("[L2] 配置被拒且已缩到单个节点, 丢弃它")
                return []
            nodes.pop(bad)
            dropped += 1
        print(f"[L2] 剔除 {dropped} 个后仍不通过, 二分再试")
        if len(nodes) > 1 and _depth < 8:
            mid = len(nodes) // 2
            return (self.prune(nodes[:mid], max_rounds=4, _depth=_depth + 1)
                    + self.prune(nodes[mid:], max_rounds=4, _depth=_depth + 1))
        return []

    def start(self, nodes: list[dict]) -> bool:
        if not MIHOMO.exists():
            print("[L2] 未找到 bin/mihomo.exe, 跳过内核测速")
            return False
        cfg = self.write_config(nodes)
        # 进程隔离: 环境变量白名单(不把父进程的密钥/令牌传进去)、独立工作目录、
        # 不共享控制台与 stdin、POSIX 下加 rlimit 并降权到 nobody
        self.proc = subprocess.Popen(
            [str(MIHOMO), "-d", str(KERNEL_DIR), "-f", str(cfg)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            cwd=str(KERNEL_DIR),
            env=sec.kernel_env(),
            creationflags=sec.kernel_creationflags(),
            preexec_fn=sec.kernel_preexec(),
        )
        for _ in range(60):
            if self.proc.poll() is not None:
                print(f"[L2] 内核启动失败 (exit {self.proc.returncode}), 配置可能被拒")
                return False
            try:
                self.api("/version", timeout=2)
                return True
            except Exception:
                time.sleep(0.5)
        print("[L2] 内核 API 未就绪")
        self.stop()
        return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


def probe_real(nodes: list[dict], timeout_ms: int = 3000, workers: int = 192,
               test_url: str = TEST_URL, target: int = 0, budget: float = 0,
               chunk: int = 1000, hist: dict | None = None,
               ttl: int = 5400, min_fails: int = 2,
               op: str = "扫描") -> list[dict]:
    """分片拉起内核做真实测速。节点名临时换成 n00000 索引, 避开中文/emoji 转义坑。

    必须分片: 内核遇到坏节点就 fail-fast 拒绝整份配置, 候选池越大越容易
    被极少数脏节点拖死(实测 1675 个里有 25+ 个)。分片后每片独立校验,
    坏节点最多毁掉一片, 而不是整轮。

    nodes 需已按优先级排序。target>0 凑够即停, budget>0 超时即停。
    """
    if not nodes:
        return []
    # L2 通过率只有百分之几, 绝大多数候选是白测的。反复实测不通的直接跳过。
    nodes, _l2skip = _negcache_filter(nodes, hist or {}, ttl, min_fails)
    if _l2skip:
        print(f"[L2] 负缓存跳过 {_l2skip} 个反复实测不通的节点, 剩 {len(nodes)} 个")
    if not nodes:
        print("[L2] 候选全被负缓存跳过")
        return []
    t0 = time.time()
    out: list[dict] = []
    tested: list[dict] = []
    t_prune = t_start = t_probe = 0.0
    n_chunks = (len(nodes) + chunk - 1) // chunk
    for ci in range(n_chunks):
        part = nodes[ci * chunk:(ci + 1) * chunk]
        if not part:
            continue
        # 每片一个新内核实例 —— 随机端口/密钥也随之一新
        k = Kernel()
        _a = time.time()
        part = k.prune(part, max_rounds=16)
        t_prune += time.time() - _a
        if not part:
            print(f"  [片 {ci+1}/{n_chunks}] 配置无法通过校验, 整片跳过")
            continue
        _a = time.time()
        started = k.start(part)
        t_start += time.time() - _a
        if not started:
            print(f"  [片 {ci+1}/{n_chunks}] 内核启动失败, 跳过")
            continue
        _a = time.time()
        tested.extend(part)
        try:
            pairs = list(zip(part, [f"n{i:05d}" for i in range(len(part))]))
            with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                for (node, _nm), delay in zip(
                        pairs, ex.map(lambda c: k.delay(c[1], timeout_ms, test_url), pairs)):
                    if delay:
                        node["_real"] = delay
                        out.append(node)
        finally:
            k.stop()
        t_probe += time.time() - _a
        print(f"  [片 {ci+1}/{n_chunks}] 累计可用 {len(out)} 个 ({time.time()-t0:.0f}s)")
        set_progress(op, "L2 内核实测", min((ci + 1) * chunk, len(nodes)), len(nodes),
                     f"已找到 {len(out)} 个")
        if target and len(out) >= target:
            print(f"[L2] 已达目标 {target} 个, 提前停止")
            break
        if budget and time.time() - t0 > budget:
            print(f"[L2] 超出 {budget:.0f}s 预算, 提前停止")
            break
    print(f"[L2] 内核实测: {len(out)}/{len(nodes)} 真能出网  ({time.time()-t0:.1f}s)")
    print(f"[L2] 细分: 配置校验 {t_prune:.1f}s | 内核启动 {t_start:.1f}s | "
          f"实际测速 {t_probe:.1f}s")
    if hist is not None and tested:
        ok_ids = {id(n) for n in out}
        _negcache_record(hist, [(n, id(n) in ok_ids) for n in tested])
    return out


# --------------------------------------------------------------------------
# 打分 / 排序
# --------------------------------------------------------------------------
L1_CACHE = STATE / "l1.json"
POOL_STATE = STATE / "pool.json"
# L1 负缓存: 记每个节点连续失败几次、最后一次什么时候失败
L1_HIST = STATE / "l1_hist.json"
# L2 负缓存: 过了 L1 但内核实测出不去的节点, 同样别每轮重复测
L2_HIST = STATE / "l2_hist.json"
# 扫描进度: 子进程写, 常驻和控制台读 —— 让界面能显示"现在跑到哪了"
PROGRESS = STATE / "progress.json"


def _load_hist(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_hist(path: Path, hist: dict, cap: int = 60000, keep: int = 40000):
    if not hist:
        return
    try:
        if len(hist) > cap:
            hist = dict(sorted(hist.items(),
                               key=lambda kv: kv[1].get("t", 0), reverse=True)[:keep])
        STATE.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(hist, separators=(",", ":")), encoding="utf-8")
    except Exception:
        pass


def load_l1_hist() -> dict:
    return _load_hist(L1_HIST)


def save_l1_hist(hist: dict):
    _save_hist(L1_HIST, hist)


def load_l2_hist() -> dict:
    return _load_hist(L2_HIST)


def save_l2_hist(hist: dict):
    _save_hist(L2_HIST, hist)


def _negcache_filter(nodes: list[dict], hist: dict, ttl: int,
                     min_fails: int) -> tuple[list[dict], int]:
    """按负缓存过滤掉"反复失败"的节点。返回 (要测的, 跳过的个数)。

    min_fails <= 0 表示关闭。
    """
    if not hist or min_fails <= 0:
        return nodes, 0
    now = time.time()
    todo, skip = [], 0
    for n in nodes:
        h = hist.get(n.get("_fp") or "")
        if h and h.get("f", 0) >= min_fails and now - h.get("t", 0) < ttl:
            skip += 1
            continue
        todo.append(n)
    return todo, skip


def _negcache_record(hist: dict, results: list[tuple[dict, bool]]):
    """把本轮结果写回负缓存。results 是 (节点, 是否成功)。"""
    now = time.time()
    for n, ok in results:
        fp = n.get("_fp")
        if not fp:
            continue
        if ok:
            hist[fp] = {"f": 0, "t": now}
        else:
            h = hist.get(fp) or {"f": 0, "t": 0}
            hist[fp] = {"f": h.get("f", 0) + 1, "t": now}
# 归一逻辑改动时递增。缓存里存的是**归一后**的节点, 规则一变旧缓存就不能复用。
L1_CACHE_VERSION = 2


def save_pool(nodes: list[dict]):
    """把当前入池的节点存下来 —— 快车道复检要靠它知道池子里现在有什么。"""
    STATE.mkdir(parents=True, exist_ok=True)
    POOL_STATE.write_text(json.dumps({"ts": time.time(), "nodes": nodes},
                                     ensure_ascii=False), encoding="utf-8")


def load_pool() -> list[dict] | None:
    if not POOL_STATE.exists():
        return None
    try:
        d = json.loads(POOL_STATE.read_text(encoding="utf-8"))
    except Exception:
        return None
    return d.get("nodes") or None


def pool_age() -> float | None:
    """池子上一次刷新距今多少秒。"""
    try:
        rep = json.loads((OUT / "report.json").read_text(encoding="utf-8"))
    except Exception:
        return None
    ts = rep.get("ts")
    if not ts:
        # 早期版本的 report 没有 ts 字段, 退回解析 generated_at
        try:
            ts = datetime.fromisoformat(str(rep.get("generated_at", ""))).timestamp()
        except Exception:
            return None
    return time.time() - float(ts)


def save_l1(nodes: list[dict]):
    STATE.mkdir(parents=True, exist_ok=True)
    L1_CACHE.write_text(json.dumps({"ts": time.time(), "v": L1_CACHE_VERSION,
                                    "nodes": nodes}, ensure_ascii=False),
                        encoding="utf-8")


def load_l1(max_age: int = 3600) -> list[dict] | None:
    """复用上一次 L1 结果 —— 调 L2 参数时不必每次重跑 60 秒 TCP 探活。"""
    if not L1_CACHE.exists():
        return None
    try:
        d = json.loads(L1_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return None
    if d.get("v") != L1_CACHE_VERSION:
        # 缓存里存的是**归一后**的节点, 归一规则一变旧缓存就不能再用。
        # 实测踩过: 新版给 vmess 补 alterId 默认值, 但 --reuse-l1 复用旧缓存,
        # 结果整片被内核拒掉, 看起来像新代码坏了。
        return None
    if time.time() - d.get("ts", 0) > max_age:
        return None
    return d.get("nodes") or None


def load_cache() -> dict:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_cache(nodes: list[dict], hist: dict):
    for n in nodes:
        h = hist.setdefault(n["_fp"], {"seen": 0, "ok": 0, "best": None})
        h["seen"] += 1
        h["ok"] += 1
        d = n.get("_real") or n.get("_tcp")
        if d and (h["best"] is None or d < h["best"]):
            h["best"] = d
    # 修剪: 只留最近 8000 条
    if len(hist) > 8000:
        keep = sorted(hist.items(), key=lambda kv: kv[1].get("ok", 0), reverse=True)[:8000]
        hist = dict(keep)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(hist, ensure_ascii=False), encoding="utf-8")


def rank(nodes: list[dict]) -> list[dict]:
    """按延迟排序。

    没有 `_tcp` 的是被 L1 放行的 QUIC 节点(它们没做 TCP 探测)。给它们一个
    中位数占位, 不能直接当 9999 —— 候选超过 l2_top 时整批排在最后会被截断
    丢掉, 那样"放行"等于白做。
    """
    known = sorted(n["_tcp"] for n in nodes if n.get("_tcp") is not None)
    mid = known[len(known) // 2] if known else 9999

    def key(n):
        return (n.get("_real") or n.get("_tcp") or mid, n.get("_region") or "ZZ")
    return sorted(nodes, key=key)


def diversify(nodes: list[dict], per_subnet: int = 4) -> list[dict]:
    """同一 /24 段最多保留 per_subnet 个。

    Cloudflare CDN 类节点(162.159.x.x / 172.64.x.x)TCP 延迟极低(40~50ms),
    会霸占 L1 排序前列, 但实测绝大多数握手即死。不做网段限流的话,
    L2 候选池会被同几段 CDN 假节点填满, 真节点根本轮不到被测试。
    """
    cnt: dict[str, int] = {}
    out: list[dict] = []
    for n in nodes:
        s = str(n.get("server") or "")
        try:
            ip = ipaddress.ip_address(s)
            key = ".".join(str(ip).split(".")[:3]) if ip.version == 4 else str(ip)[:16]
        except ValueError:
            key = s.rsplit(".", 1)[0] if "." in s else s
        if cnt.get(key, 0) >= per_subnet:
            continue
        cnt[key] = cnt.get(key, 0) + 1
        out.append(n)
    return out


# --------------------------------------------------------------------------
# 生成配置
# --------------------------------------------------------------------------
def _quote(s) -> str:
    """一律双引号包裹并转义 —— 键名和字符串值都走这里。

    键名必须引号化。之前键名是裸写的, 攻击者只要在键名里塞一个 YAML 读取端
    认作换行的字符(U+2028 / U+2029 / U+0085), 键名就会在序列化时断成两行,
    后面那半截变成新的顶层键 —— 实测能往产物注入 tun / tunnels / hosts,
    绕过 harden_kernel_config 的 pop("tun")。
    """
    s = _CTRL_RE.sub("", str(s))
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _scalar(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    return _quote(v)


def _yaml_lines(obj, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = _quote(k)
            if isinstance(v, (dict, list)) and len(v):
                lines.append(f"{pad}{key}:")
                lines += _yaml_lines(v, indent + 1)
            elif isinstance(v, list):
                lines.append(f"{pad}{key}: []")
            elif isinstance(v, dict):
                lines.append(f"{pad}{key}: {{}}")
            else:
                lines.append(f"{pad}{key}: {_scalar(v)}")
    elif isinstance(obj, list):
        for it in obj:
            if isinstance(it, dict):
                sub = _yaml_lines(it, indent + 1)
                if not sub:
                    lines.append(f"{pad}- {{}}")
                    continue
                lines.append(f"{pad}- {sub[0].strip()}")
                lines += sub[1:]
            elif isinstance(it, list):
                lines.append(f"{pad}-")
                lines += _yaml_lines(it, indent + 1)
            else:
                lines.append(f"{pad}- {_scalar(it)}")
    return lines


def _dump_yaml(obj) -> str:
    return "\n".join(_yaml_lines(obj)) + "\n"


def strip_private(p: dict) -> dict:
    return {k: v for k, v in p.items() if not k.startswith("_")}


def build_clash(nodes: list[dict], title: str = None) -> str:
    title = title or f"{ver.__title__} · 全量"
    proxies = [strip_private(n) for n in nodes]

    # 先把地区分组名算出来 —— 节点名一旦和分组名相同, 内核会报
    # "loop is detected in ProxyGroup" 并拒绝整份配置, 必须在命名阶段避开
    reserved = set()
    for code, cnt in Counter((n.get("_region") or "XX") for n in nodes).items():
        if cnt >= 2:
            f, c = region_label(code)
            reserved.add(f"{f} {c}")

    # 名字去重 + 避开保留名
    seen: dict[str, int] = {}
    for i, p in enumerate(proxies):
        nm = p["name"]
        if nm in reserved:
            nm = f"{nm} · {str(nodes[i].get('server') or '')[:18]}"
        if nm in seen:
            seen[nm] += 1
            nm = f"{nm} #{seen[nm]}"
        else:
            seen[nm] = 0
        p["name"] = nm
    names = [p["name"] for p in proxies]

    by_region: dict[str, list[str]] = {}
    for n, p in zip(nodes, proxies):
        by_region.setdefault(n.get("_region") or "XX", []).append(p["name"])
    # 地区组按节点数排序
    regions = sorted(by_region.items(), key=lambda kv: len(kv[1]), reverse=True)

    group_names = []
    groups = []
    for code, members in regions:
        if len(members) < 2:
            continue
        flag, cn = region_label(code)
        gname = f"{flag} {cn}"
        group_names.append(gname)
        groups.append({
            "name": gname, "type": "url-test", "url": TEST_URL,
            "interval": 180, "tolerance": 60, "lazy": False,
            "proxies": members,
        })

    fast = names[:30]
    groups.insert(0, {
        "name": "♻️ 自动选择", "type": "url-test", "url": TEST_URL,
        "interval": 120, "tolerance": 40, "lazy": False, "proxies": names,
    })
    groups.insert(1, {
        "name": "🛡️ 故障转移", "type": "fallback", "url": TEST_URL,
        "interval": 120, "proxies": fast or names,
    })
    groups.insert(2, {
        "name": "🚀 节点选择", "type": "select",
        "proxies": ["♻️ 自动选择", "🛡️ 故障转移", "DIRECT"] + group_names + names,
    })

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        # 不读进程名 —— 少一条本地信息泄露面
        "find-process-mode": "off",
        # 故意不写 external-controller: 订阅文件不该替内核开控制端口,
        # 端口和密钥交给客户端自己管
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True, "ipv6": False,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "*.localdomain",
                               "localhost.ptlogin2.qq.com", "time.*.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["223.5.5.5", "119.29.29.29", "https://doh.pub/dns-query"],
            # 不用 fallback-filter.geoip —— 它需要下载 MMDB, 离线或墙内会
            # 直接让整份配置校验失败(实测 90 秒超时后 "test failed")
        },
        "proxies": proxies,
        "proxy-groups": groups,
        # 规则顺序即优先级: 云元数据拒绝 > 敏感站点直连 > 国内域名直连 >
        # 内网直连 > 国内 IP 直连 > 本地直连 > 其余走代理。
        # 国内那两段见 sec.build_security_rules —— 少了它们, 国内流量
        # (包括所有国内网站)会跟着兜底的 MATCH 一起进免费节点。
        "rules": list(sec.SECURITY_RULES) + ["MATCH,🚀 节点选择"],
    }
    header = (
        f"# {title}\n"
        f"# 生成时间: {ts}   节点数: {len(proxies)}   地区: {len(regions)}\n"
        f"# {sec.cn_summary()}\n"
        f"# 由 freeVPN 自动聚合去重 + 双层探活生成, 重新生成会覆盖本文件\n"
    )
    text = header + _dump_yaml(cfg)

    # 自校验: 反解产物, 顶层键必须与预期完全一致。
    # 键名转义万一有漏, 这是最后一道兜底 —— 与其把注入了 tun 的配置交给
    # 客户端, 不如在这里把多出来的键剔掉。
    if _yaml is not None:
        try:
            got = set((_yaml.safe_load(text) or {}).keys())
        except Exception as e:
            raise RuntimeError(f"产物 YAML 无法反解, 拒绝输出: {e}") from e
        extra = got - _TOP_LEVEL_KEYS
        if extra:
            print(f"[安全] 产物出现意外顶层键 {sorted(extra)}, 已剔除 (疑似 YAML 顶层注入)")
            for k in extra:
                cfg.pop(k, None)
            text = header + _dump_yaml(cfg)
    return text


def build_b64(nodes: list[dict]) -> str:
    links = []
    for n in nodes:
        try:
            lk = proxy_to_link(n)
        except Exception:
            lk = None
        if lk:
            links.append(lk)
    return base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")


def write_outputs(nodes: list[dict], stats: dict, l1_total: int, l2_total: int | None,
                  audit=None, dedupe_total: int | None = None):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "freevpn.yaml").write_text(build_clash(nodes, f"{ver.__title__} · 全量"), encoding="utf-8")
    (OUT / "freevpn.txt").write_text(build_b64(nodes), encoding="utf-8")

    by_region: dict[str, list[dict]] = {}
    for n in nodes:
        by_region.setdefault(n.get("_region") or "XX", []).append(n)
    for code, members in by_region.items():
        if len(members) < 2:
            continue
        (OUT / f"{code.lower()}.yaml").write_text(
            build_clash(members, f"{ver.__title__} · {region_label(code)[1]}"),
            encoding="utf-8")
        (OUT / f"{code.lower()}.txt").write_text(build_b64(members), encoding="utf-8")

    report = {
        "version": ver.__version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ts": time.time(),
        "sources": {k: v for k, v in stats.items()},
        "sources_ok": sum(1 for v in stats.values() if v.get("ok")),
        "sources_total": len(stats),
        # after_dedupe 必须是**去重后**的数量。以前这里填的是 l1_total,
        # 于是状态页上"去重后"显示的是 L1 存活数 —— 两个阶段的数字看起来一样,
        # 用户以为去重没起作用。
        "after_dedupe": dedupe_total if dedupe_total is not None else l1_total,
        "after_l1": l1_total,
        "after_l2": l2_total,
        "final": len(nodes),
        "regions": {k: len(v) for k, v in sorted(by_region.items(), key=lambda kv: -len(kv[1]))},
        # audit 可能是 AuditReport, 也可能是上一轮报告里的 dict(快车道复用)
        "audit": (audit.as_dict() if hasattr(audit, "as_dict") else (audit or {})),
        "fastest": [
            {"name": n["name"], "region": n.get("_region"), "type": n["type"],
             "tcp": n.get("_tcp"), "real": n.get("_real")}
            for n in nodes[:25]
        ],
    }
    (OUT / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


# --------------------------------------------------------------------------
# 一键导入到已装的客户端
# --------------------------------------------------------------------------
# 客户端注册的深链协议。装了哪个就能用哪个, 顺序即优先级。
IMPORT_SCHEMES = ("clash", "clash-verge", "mihomo", "flclash")
IMPORT_NAME = ver.__title__


def detect_clients() -> list[tuple[str, str]]:
    """扫注册表, 返回 [(协议, 处理程序命令行)] —— 装了哪些支持一键导入的客户端。"""
    found: list[tuple[str, str]] = []
    try:
        import winreg
    except ImportError:
        return found
    for scheme in IMPORT_SCHEMES:
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, rf"Software\Classes\{scheme}\shell\open\command") as k:
                    cmd = winreg.QueryValueEx(k, "")[0]
            except OSError:
                continue
            found.append((scheme, cmd))
            break
    return found


def import_link(scheme: str, sub_url: str) -> str:
    """拼深链。客户端收到后会弹窗让你确认导入。"""
    return f"{scheme}://install-config?" + urllib.parse.urlencode(
        {"url": sub_url, "name": IMPORT_NAME})


def open_link(link: str) -> bool:
    try:
        if os.name == "nt":
            os.startfile(link)
        else:
            subprocess.Popen(["xdg-open", link])
        return True
    except Exception as e:
        print(f"[!] 打开链接失败: {type(e).__name__}: {e}")
        return False


def client_pids(exe: str) -> set[int]:
    """某个客户端进程当前的所有 PID。"""
    try:
        r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {exe}", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, timeout=15,
                           encoding=sec.console_encoding(), errors="replace",
                           creationflags=sec.hidden_flags())
        pids = set()
        for line in (r.stdout or "").splitlines():
            parts = [x.strip('"') for x in line.split('","')]
            if len(parts) >= 2 and parts[1].isdigit():
                pids.add(int(parts[1]))
        return pids
    except Exception:
        return set()


def launch_deeplink(link: str, exe: str) -> tuple[bool, str]:
    """触发深链, 并判断客户端到底有没有接住。

    os.startfile 是"发射后不管" —— 它立刻返回, 成功失败我们都不知道。
    用户那边只会看到客户端自己的报错弹窗(或者干脆没反应)。

    这里在发射前后各看一次进程: 新起的实例如果几秒内就退了, 基本就是启动失败
    (常见原因: 单例锁拿不到、沙箱/杀软拦命名对象、客户端本身状态坏了)。
    """
    before = client_pids(exe)
    if not open_link(link):
        return False, "连深链都没能打开"

    # 已经有一个在跑的话, 新实例转发完 URL 就该退出 —— 那是正常流程, 不算失败
    if before:
        time.sleep(2.5)
        return True, "已转发给正在运行的客户端"

    for _ in range(12):                      # 最多等 6 秒
        time.sleep(0.5)
        now = client_pids(exe)
        if now - before:
            time.sleep(2.0)
            alive = client_pids(exe)
            if alive - before:
                return True, "客户端已启动"
            return False, "客户端起来了又马上退出 —— 它自己启动失败了"
    return False, "等了 6 秒也没看到客户端进程"


VERGE_DIRS = [
    Path(os.environ.get("APPDATA", "")) / "io.github.clash-verge-rev.clash-verge-rev",
    Path(os.environ.get("APPDATA", "")) / "io.github.clash-verge-rev.clash-verge",
    Path(os.environ.get("APPDATA", "")) / "clash-verge",
]


def find_verge_dir() -> Path | None:
    for d in VERGE_DIRS:
        if d and (d / "profiles.yaml").exists():
            return d
    return None


def verge_running() -> bool:
    try:
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq clash-verge.exe"],
                           capture_output=True, text=True, timeout=15,
                           encoding=sec.console_encoding(), errors="replace",
                           creationflags=sec.kernel_creationflags())
        return "clash-verge.exe" in (r.stdout or "")
    except Exception:
        return False


def probe_sub_url(url: str, timeout: float = 8.0) -> int:
    """拉一下订阅地址, 返回 HTTP 状态码 (失败返回 0)。

    写进客户端之前必须自测 —— 端口上跑的可能是**另一份** freeVPN:
    源码版和打包版各有自己的 state/token.txt, 令牌不同, 还会互相抢端口。
    用 A 的令牌写进客户端、而实际在监听的是 B, 客户端只会拿到 401,
    而且从表面完全看不出原因。
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def inject_verge(sub_url: str, activate: bool = False,
                 restart_client: bool = False) -> bool:
    """把池子直接写成 Clash Verge Rev 的一条远程订阅。

    **不需要先关客户端。** 实测 Clash Verge 只在启动时读一次 profiles.yaml,
    之后既不监听它、退出时也不重写它 —— 运行中直接写是安全的。
    代价是客户端要重启才能看到新条目, 那是 `restart_client=True` 干的事。

    (这里以前有"客户端必须已退出"的硬性检查, 依据是"退出时会整个写回"。
     实测不成立, 白让用户多关一次客户端, 而且运行中就只能退到不稳定的深链路径。)
    """
    import yaml as _y

    d = find_verge_dir()
    if not d:
        print("[!] 没找到 Clash Verge 的配置目录 (profiles.yaml)")
        return False

    running = verge_running()

    # 写之前先自测一遍这个地址。
    # 分情况处理 —— 一视同仁地"失败就退深链"是错的: 深链在有些机器上会直接
    # 崩(客户端单例锁拿不到, os error 5), 反而制造一个吓人的报错弹窗。
    code = probe_sub_url(sub_url)
    if code in (401, 403):
        print(f"[!] 订阅地址自测返回 HTTP {code} —— 令牌不对, 写了客户端也拉不到。")
        print(f"    {sub_url}")
        print("    8787 端口上跑的可能是**另一份** freeVPN: 源码版和打包版各有自己的")
        print("    state/token.txt, 令牌不同, 而且会互相抢端口。只留一个再试。")
        return False
    if code != 200:
        # 404/000 多半是第一轮扫描还没跑完(pool.yaml 还没生成)。
        # 这不是错误 —— 客户端会自己重试, 所以照样写。
        print(f"[*] 订阅地址暂时还拉不到 (HTTP {code}) —— 多半是第一轮扫描没跑完。")
        print("    照样写入, 客户端过一会儿自己会拉到。")

    idx = d / "profiles.yaml"

    # 先探一下这个目录到底能不能写。写不了的话后面每一步都会以
    # "Permission denied" 收场, 与其让用户对着一串英文错误发呆,
    # 不如在这里就说清楚是什么、怎么办。
    probe = d / ".freevpn-write-test"
    try:
        probe.write_text("x", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except Exception as e:
        print(f"[!] 没有权限写 Clash Verge 的配置目录")
        print(f"    目录: {d}")
        print(f"    原因: {type(e).__name__}: {e}")

        # 自己判断一下是"这一个目录的问题"还是"整个程序被关起来了"。
        # 后者很常见: 程序放在某个被策略限制的目录里(比如 agent 的工作区),
        # 那些目录下的可执行文件只能写工作区内部。诊断出来用户才知道往哪走。
        tmp = Path(os.environ.get("TEMP", ".")) / f".freevpn-wt-{os.getpid()}"
        try:
            tmp.write_text("x", encoding="utf-8")
            tmp.unlink(missing_ok=True)
            confined = False
        except Exception:
            confined = True

        if confined:
            print("    >>> 连系统临时目录都写不了 —— 本程序被限制只能写自己附近。")
            print(f"        程序位置: {sec.app_root()}")
            print("        这种限制是按**路径**生效的(常见于 agent 工作区、受管目录)。")
            print("        把整个文件夹移到别处再跑, 例如:")
            print("            C:\\freeVPN\\")
            print("        然后从那里启动。移过去之后 state/ 要一起带, 否则订阅令牌会变。")
        else:
            print("    常见情况:")
            print("      · Clash Verge 是以管理员身份运行的, 而本程序不是")
            print("        → 用管理员身份重跑本程序, 或把 Clash Verge 改成普通权限启动")
            print("      · 该目录被安全软件锁了")
        print("    → 退路: 手动添加订阅 (订阅页 -> 新建 -> 远程):")
        print(f"      {sub_url}")
        return False
    # 备份带时间戳轮转, 保留最近 5 份。之前是"备份不存在才备份", 第二次运行
    # 时备份还是第一次的旧内容, 与用户以为的"原始配置"不一致。
    #
    # 刻意不用 shutil.copy2: 它除了拷内容还要拷文件元数据(copystat)。
    # 备份只要内容就够了, 少一步少一个失败点。
    #
    # **备份失败不再中止导入。** 以前是"备份不了就不改你的配置", 听着稳妥,
    # 实际后果是: 环境里有一点权限异常就整个导入瘫掉, 用户只看到"导入没成功"
    # 却完全不知道为什么 —— 而我们要做的改动只是"加一条自己的订阅"。
    # 备份是保险, 不是前提。
    raw = b""
    try:
        raw = idx.read_bytes()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        (d / f"profiles.yaml.freevpn.{stamp}.bak").write_bytes(raw)
        olds = sorted(d.glob("profiles.yaml.freevpn.*.bak"))
        for old in olds[:-5]:
            old.unlink(missing_ok=True)
        print(f"[*] 已备份原配置: profiles.yaml.freevpn.{stamp}.bak")
    except Exception as e:
        print(f"[!] 备份失败 ({type(e).__name__}: {e})")
        # 退一步: 备份到我们自己的 state/ 里。内容一样能救回来。
        try:
            if not raw:
                raw = idx.read_bytes()
            alt = STATE / f"profiles.yaml.{datetime.now():%Y%m%d-%H%M%S}.bak"
            STATE.mkdir(parents=True, exist_ok=True)
            alt.write_bytes(raw)
            print(f"    已改存到: {alt}")
        except Exception as e2:
            print(f"    改存也失败 ({type(e2).__name__}), 继续导入 —— 这次改动只是"
                  f"加一条订阅条目, 在客户端里可以删掉")
    try:
        data = _y.safe_load(idx.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"[!] 解析 profiles.yaml 失败, 未做任何改动: {e}")
        return False
    if not isinstance(data, dict):
        print("[!] profiles.yaml 结构异常, 未做任何改动")
        return False

    # 先清掉本程序以前导入过的条目, 免得改名/换端口后留一堆孤儿。
    # 光按名字认不够: 改名(「VPN 池」-> freeVPN)之前导入的那条名字不一样,
    # 会一直留在列表里, 而且可能还是 current —— 用户看到的配置是旧的。
    # 所以再按 URL 认一遍: 指向本机订阅服务的就算自己的。
    try:
        _port = urllib.parse.urlparse(sub_url).port or 8787
    except Exception:
        _port = 8787
    self_url_mark = f"127.0.0.1:{_port}/sub/"

    def is_ours(it) -> bool:
        if not isinstance(it, dict):
            return False
        if it.get("name") == IMPORT_NAME:
            return True
        return self_url_mark in (it.get("url") or "")

    items = [it for it in (data.get("items") or []) if not is_ours(it)]
    uid = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    items.append({
        "uid": uid,
        "type": "remote",
        "name": IMPORT_NAME,
        "file": f"{uid}.yaml",
        "url": sub_url,
        "updated": int(time.time()),
        # 客户端拉取间隔跟池子的完整扫描间隔对齐, 免得池子刷新了客户端还在用旧的
        "option": {"update_interval": max(5, int(load_conf().get("interval", 30) or 30)),
                   "allow_auto_update": True},
    })
    data["items"] = items

    # `current` 必须指向一个**真实存在**的条目。
    # 上面刚把本程序以前导入的条目清掉了(改名、换端口留下的孤儿), 如果
    # current 正好指着其中一条, 它就悬空了 —— Clash Verge 启动时会直接报
    #   failed to read current profile "xxxx"
    # 然后退回默认配置。这个错误是删条目引入的, 所以删完必须补上。
    valid_uids = {it.get("uid") for it in items
                  if isinstance(it, dict) and it.get("uid")}
    cur = data.get("current")
    if activate:
        data["current"] = uid
        print("    并已设为当前使用中的配置")
    elif not cur or cur not in valid_uids:
        data["current"] = uid
        if cur:
            print(f"    (原来的 current「{cur}」指向的条目已经没了 —— "
                  f"这是之前清理孤儿条目留下的悬空引用, 已改指向本条目)")
        else:
            print("    (原配置没有 current, 已设为本条目)")

    payload = ("# Profiles Config for Clash Verge\n\n"
               + _y.safe_dump(data, allow_unicode=True, sort_keys=False))
    # 原子替换: 直接 write_text 会先把文件截断为 0 再逐块写, 实测能抓到
    # 0 字节的中间态 —— 那期间崩溃/断电, 用户拿到的就是半个 YAML,
    # Clash Verge 会拒绝加载甚至丢掉整个订阅列表。
    #
    # tmp 名必须带随机后缀。原来固定成 `profiles.yaml.freevpn.tmp`,
    # 而 Windows 上 os.link 不需要管理员权限 —— 本机攻击者可以预置一个
    # 指向任意文件的硬链接, 我们 write_text 就把那个文件覆盖了。
    # (实测: 受害者文件被替换成我们写的 YAML 内容。)
    tmp = idx.with_name(f"{idx.name}.{secrets.token_hex(6)}.tmp")
    try:
        if tmp.exists() or tmp.is_symlink():
            print(f"[!] 临时文件已存在, 中止: {tmp.name}")
            return False
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, idx)          # Windows 上 os.replace 是原子的
    except Exception as e:
        print(f"[!] 写入失败, 原配置未被破坏: {type(e).__name__}: {e}")
        print(f"    备份在: {d} (profiles.yaml.freevpn.*.bak)")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False

    # 顺手落一份内容, 客户端不用等首次拉取
    try:
        (d / "profiles").mkdir(exist_ok=True)
        (d / "profiles" / f"{uid}.yaml").write_text(
            (OUT / "freevpn.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass

    print(f"[✓] 已写入订阅条目: {IMPORT_NAME}  (uid {uid})")
    print(f"    自动更新间隔: 30 分钟")

    # 实测结论(推翻了之前的假设): Clash Verge **只在启动时读一次** profiles.yaml,
    # 之后既不监听它、退出时也不重写它。所以
    #   ① 运行时直接写是安全的, 不会被覆盖 —— 不需要先关掉客户端
    #   ② 但客户端要重启才能看到新订阅
    # 之前那句"退出时会整个写回, 运行中改等于白改"是错的, 白让用户多关一次客户端。
    if running:
        if restart_client:
            print("\n[*] 重启 Clash Verge 让它读到新订阅 ...")
            close_verge()
            relaunch_verge()
        else:
            print("\n[*] Clash Verge 正在运行 —— 它只在启动时读配置,")
            print("    所以新订阅要**重启客户端**才会出现在列表里。")
            print("    (加 --restart 可以自动帮你重启)")
    else:
        print("    打开 Clash Verge 即可看到")
    return True


def fast_refresh(args) -> dict:
    """快车道: 只重测池内现有节点, 把死掉的踢掉, 不重新拉源。

    完整扫描要 6~10 分钟, 而免费节点寿命常常只有几小时 —— 中间死掉的会一直
    卡在客户端里。所以每几分钟把池内节点重测一遍, 成本只有几秒。
    存活率太低说明这批节点整体过期了, 直接升级为完整扫描。
    """
    cur = load_pool()
    if not cur:
        return run_cycle(args)
    print(f"\n[{datetime.now():%H:%M:%S}] 快车道复检池内 {len(cur)} 个节点 ...")
    for n in cur:
        n.pop("_real", None)
    set_progress("快车道复检", "L2 内核实测", 0, len(cur))
    alive = probe_real(cur, timeout_ms=args.l2_timeout,
                       workers=getattr(args, "l2_workers", 192),
                       test_url=getattr(args, "test_url", TEST_URL), chunk=250,
                       op="快车道复检")
    floor = max(5, len(cur) // 3)
    if len(alive) < floor:
        print(f"[!] 只活下来 {len(alive)}/{len(cur)} (低于 {floor}), 升级为完整扫描")
        return run_cycle(args)
    alive = rank(alive)
    save_pool(alive)
    try:
        prev = json.loads((OUT / "report.json").read_text(encoding="utf-8"))
        stats = prev.get("sources") or {}
        prev_audit = prev.get("audit") or {}
    except Exception:
        stats, prev_audit = {}, {}
    # 快车道不重新拉源, 审计统计只能沿用上一轮 —— 否则状态页会显示"拦截 0"
    report = write_outputs(alive, stats, len(alive), len(alive), prev_audit)
    clear_progress()
    print(f"[✓] 快车道完成: 池内 {len(alive)} 个仍可用")
    return report


def load_conf() -> dict:
    """读可选的 pool.conf.json。

    命令行参数优先级更高 —— 这里只提供默认值, 方便把"每 30 分钟完整扫描、
    每 5 分钟快车道"这类设置固定下来, 不用每次启动都敲一遍。

    读取时先找 exe 旁边的（用户可编辑）, 再找打包进 exe 的默认值。
    """
    p = sec.find_resource("pool.conf.json")
    if not p:
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] {p.name} 解析失败, 已忽略: {e}")
        return {}
    return d if isinstance(d, dict) else {}


def _next_slot(interval_min: int, now: float | None = None) -> float:
    """下一个对齐时钟刻度的执行时刻(epoch 秒)。

    排程必须对齐刻度, 不能是"上次跑完 + 间隔": 完整扫描本身要 4~5 分钟,
    后者会让 30 分钟档变成 35 分钟, 而且每轮继续往后漂。
    对齐之后 30 分钟档永远落在 :00 / :30, 5 分钟档落在 :00 :05 :10 …, 与扫描耗时无关。
    """
    now = time.time() if now is None else now
    step = max(1, interval_min) * 60
    return (math.floor(now / step) + 1) * step


def _slot_str(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def run_child(argv: list[str], logfile: Path | None = None) -> int:
    """在子进程里跑一轮扫描。

    主进程只做 HTTP 服务, 扫描全部丢给子进程 —— 同一个进程里跑 500 并发 TCP
    探测会把 GIL 抢满, 服务线程被饿着, 实测订阅请求会从"秒回"抖到 10 秒,
    客户端那边就表现为超时失败。
    """
    cmd = sec.self_cmd() + argv
    fh = None
    kw: dict = {
        # 没有这个标志, 从无控制台的进程(pythonw / 计划任务)起子进程时
        # Windows 会给它分配一个新控制台 —— 屏幕上闪一个黑窗。
        "creationflags": sec.kernel_creationflags(),
    }
    if logfile:
        try:
            fh = open(logfile, "a", encoding="utf-8", buffering=1)
            kw["stdout"] = fh
            kw["stderr"] = fh
        except Exception:
            fh = None
    try:
        return subprocess.call(cmd, cwd=str(ROOT), **kw)
    except Exception as e:
        print(f"[!] 子进程启动失败: {type(e).__name__}: {e}")
        return 1
    finally:
        if fh:
            fh.close()


def cmd_status(args):
    """一眼看清池子现在什么状态。"""
    rep = {}
    try:
        rep = json.loads((OUT / "report.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    age = pool_age()
    print("=" * 60)
    print(f"  {ver.__title__} 状态  (v{ver.__version__})")
    print("=" * 60)
    if not rep:
        hint = f"{ver.__app_name__}.exe all" if sec.is_frozen() else "python pool.py all"
        print(f"  还没跑过任何一轮 —— 先跑  {hint}")
        return 1
    when = rep.get("generated_at", "?")
    if age is None:
        age_s = "?"
    elif age < 90:
        age_s = f"{age:.0f} 秒前"
    elif age < 5400:
        age_s = f"{age/60:.0f} 分钟前"
    else:
        age_s = f"{age/3600:.1f} 小时前"
    fresh = "新鲜" if (age or 0) < 3600 else ("偏旧" if (age or 0) < 10800 else "已过期")
    print(f"  上次刷新      {when}  ({age_s}, {fresh})")
    print(f"  入池节点      {rep.get('final', 0)} 个")
    print(f"  覆盖地区      {len(rep.get('regions') or {})} 个")
    print(f"  源可用        {rep.get('sources_ok', 0)}/{rep.get('sources_total', 0)}")
    au = rep.get("audit") or {}
    print(f"  安全审计      拦截 {au.get('blocked', 0)} / 告警 {au.get('warned', 0)}")

    listening = None
    try:
        import socket as _s
        for port in (args.port,):
            with _s.socket() as sk:
                sk.settimeout(1)
                listening = (sk.connect_ex(("127.0.0.1", port)) == 0)
    except Exception:
        pass
    print(f"  订阅服务      {'运行中' if listening else '未运行'}  (127.0.0.1:{args.port})")

    running = False
    # 读 daemon 写的 pid 文件 —— 不起子进程, 所以不会闪控制台窗口, 也快得多
    # (以前这里跑 wmic, 每次约 1 秒并且会弹窗)
    try:
        raw = (STATE / "daemon.pid").read_text(encoding="utf-8")
        running = any(sec.pid_alive(int(x)) for x in raw.split() if x.strip().isdigit())
    except Exception:
        running = False
    print(f"  常驻刷新      {'运行中 (会自动更新)' if running else '未运行'}")
    full = max(5, getattr(args, "interval", 30))
    fast = max(1, getattr(args, "fast", 5))
    print(f"  排程          完整扫描每 {full} 分钟 / 快车道每 {fast} 分钟 (对齐时钟刻度)")
    if running:
        print(f"  下次完整扫描  {_slot_str(_next_slot(full))}")
        print(f"  下次快车道    {_slot_str(_next_slot(fast))}")
    else:
        print("                —— 双击 start.bat 启动常驻, 或 python pool.py daemon")
    print("=" * 60)
    return 0


TASK_NAME = ver.__app_name__
STARTUP_DIR = (Path(os.environ.get("APPDATA", ""))
               / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
STARTUP_VBS = STARTUP_DIR / f"{ver.__app_name__}.vbs"


def cmd_autostart(args):
    """开机自启。

    走"启动文件夹 + VBS 隐藏启动", 不用计划任务 —— schtasks 建 ONLOGON 任务
    需要管理员权限(实测直接 Access is denied), 而启动文件夹是当前用户可写的,
    取消也简单: 删掉那个 .vbs 就行。
    """
    if args.remove:
        if STARTUP_VBS.exists():
            STARTUP_VBS.unlink()
            print("[✓] 已取消开机自启")
            print(f"    (删除了 {STARTUP_VBS})")
            return 0
        print("[*] 本来就没设过自启")
        return 0

    if not STARTUP_DIR.exists():
        print(f"[!] 找不到启动文件夹: {STARTUP_DIR}")
        return 1

    log = ROOT / "state" / "daemon.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    # 打包后要启动的是 exe 自己; 源码运行时优先用 pythonw.exe(完全没有控制台,
    # 不会闪黑框)
    base = sec.self_cmd()
    if not sec.is_frozen():
        pyw = Path(base[0]).with_name("pythonw.exe")
        if pyw.exists():
            base = [str(pyw)] + base[1:]
    quoted = " ".join(f'""{p}""' for p in base)

    # 注意: .vbs 必须是纯 ASCII —— wscript 按系统 ANSI 码页读它,
    # UTF-8 中文会被读成乱码, 严重时直接语法错误
    vbs = (
        "' freeVPN autostart - generated by the app itself\n"
        "' Delete this file to disable.\n"
        'Set sh = CreateObject("WScript.Shell")\n'
        f'sh.Run "{quoted} daemon --port {args.port} --interval {args.interval} '
        f'--log ""{log}""", 0, False\n'
    )
    try:
        STARTUP_VBS.write_text(vbs, encoding="ascii")
    except Exception as e:
        print(f"[!] 写入失败: {e}")
        return 1

    print("[✓] 已设置开机自启")
    print(f"    方式    {STARTUP_VBS}")
    print(f"    解释器  {py.name}")
    print(f"    日志    {log}")
    print()
    print("    下次登录 Windows 后它会在后台自己跑, 不弹窗口。")
    print("    看是否在跑:  python pool.py status")
    print("    看日志:      type state\\daemon.log")
    print("    取消自启:    python pool.py autostart --remove")
    return 0


def verge_exe() -> str:
    """找到 clash-verge.exe 的真实路径（用来关掉它 / 重新拉起它）。"""
    for scheme, cmd in detect_clients():
        if "clash-verge" in cmd.lower():
            m = re.search(r'"([^"]+clash-verge\.exe)"', cmd, re.I)
            if m and Path(m.group(1)).exists():
                return m.group(1)
    for p in (r"C:\Program Files\Clash Verge\clash-verge.exe",
              r"C:\Program Files (x86)\Clash Verge\clash-verge.exe"):
        if Path(p).exists():
            return p
    return ""


def close_verge(timeout: float = 18.0) -> bool:
    """关掉 Clash Verge, 等它真正退出。

    先温和请求(taskkill 不带 /F), 给它机会把内存里的配置写回磁盘;
    超时还活着才强杀。它退出时会把 profiles.yaml 整个重写一遍,
    所以必须等它真的走完, 不能刚发完信号就去改文件。
    """
    pids = client_pids("clash-verge.exe")
    if not pids:
        return True
    print(f"[*] 关闭 Clash Verge ({len(pids)} 个进程) ...")
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid)],
                       capture_output=True, creationflags=sec.hidden_flags())
    waited = 0.0
    while waited < timeout:
        time.sleep(0.5)
        waited += 0.5
        if not client_pids("clash-verge.exe"):
            print(f"    已退出 (等了 {waited:.1f}s)")
            return True
    print("    温和关闭超时, 强制结束")
    failed = []
    for pid in client_pids("clash-verge.exe"):
        # 必须显式给 encoding —— taskkill 输出的是系统 ANSI 码页(中文系统是 GBK),
        # 交给 Python 按 UTF-8 解会抛 UnicodeDecodeError, 而且是在读取线程里抛,
        # 打出一堆看不懂的栈
        r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, text=True,
                           encoding=sec.console_encoding(), errors="replace",
                           creationflags=sec.hidden_flags())
        if r.returncode != 0:
            failed.append((pid, (r.stderr or r.stdout or "").strip()[:80]))
    time.sleep(2.0)
    left = client_pids("clash-verge.exe")
    if left:
        print(f"    [!!] 还有 {len(left)} 个进程没退掉: {sorted(left)}")
        for pid, why in failed:
            print(f"         PID {pid}: {why}")
        # 权限不够是常见原因(比如它是以管理员身份跑的) —— 说清楚,
        # 别让用户以为程序卡住了
        print("         如果提示「拒绝访问」, 说明它权限比本程序高,")
        print("         在托盘图标上右键退出, 或者用管理员身份重跑本程序。")
        return False
    print("    已强制结束")
    return True


def relaunch_verge() -> bool:
    """把 Clash Verge 重新拉起来, **并确认它真的起来了**。

    有些机器上它拿不到单例锁就直接退出 (os error 5) —— 那种情况必须如实报出来。
    只说一句"已重新打开", 用户会对着托盘里什么都没有的界面发呆, 然后以为
    订阅导入失败了, 其实文件早就写好了。
    """
    exe = verge_exe()
    if not exe:
        print("[!] 找不到 clash-verge.exe, 手动打开客户端即可 (订阅已经写好了)")
        return False
    before = client_pids("clash-verge.exe")
    try:
        subprocess.Popen([exe], creationflags=sec.hidden_flags())
    except Exception as e:
        print(f"[!] 重新打开失败: {e}")
        print("    手动双击图标打开一次即可, 订阅已经写好了。")
        return False

    for _ in range(16):                 # 最多等 8 秒
        time.sleep(0.5)
        if client_pids("clash-verge.exe") - before:
            time.sleep(1.5)             # 再等一会儿, 看它会不会自己退掉
            if client_pids("clash-verge.exe"):
                print("[*] 已重新打开 Clash Verge")
                return True
            print("[!] Clash Verge 起来了又马上退出 —— 它自己启动失败了")
            print("    (常见原因: 拿不到单例锁, 报 os error 5 / 拒绝访问)")
            print("    手动双击图标打开一次即可, **订阅已经写好了**。")
            return False
    print("[!] 没看到 Clash Verge 进程起来")
    print("    手动双击图标打开一次即可, **订阅已经写好了**。")
    return False


def cmd_diag_write(args):
    """诊断: 本程序到底能往哪些地方写。

    打包成 exe 之后写 Clash Verge 配置目录会 Permission denied, 而同一个
    路径用 python 直接跑却没事。与其猜, 不如把常见位置逐个试一遍,
    把"边界在哪"一次问清楚。
    """
    print("=" * 62)
    print(f"  写入权限诊断  ({ver.__title__} v{ver.__version__})")
    print("=" * 62)
    print(f"  可执行文件: {sys.executable}")
    print(f"  frozen:     {sec.is_frozen()}")
    print(f"  当前用户:   {os.environ.get('USERNAME')}")
    print(f"  APPDATA:    {os.environ.get('APPDATA')}")
    print()

    targets = [
        ("程序自己的目录", sec.app_root()),
        ("程序 state/", STATE),
        # 这两个是关键对照组: 都在 E:\AI 下但在程序目录之外。
        # 能写 -> 限制是"工作区"级的; 写不了 -> 限制是"只允许自己目录"。
        ("上一级目录 (E:\\AI)", sec.app_root().parent),
        ("同级新建目录", sec.app_root().parent / "_writecheck"),
        ("%TEMP%", Path(os.environ.get("TEMP", "."))),
        ("%USERPROFILE%", Path(os.environ.get("USERPROFILE", "."))),
        ("%APPDATA% 根", Path(os.environ.get("APPDATA", "."))),
        ("%LOCALAPPDATA% 根", Path(os.environ.get("LOCALAPPDATA", "."))),
        ("Clash Verge 配置目录", find_verge_dir() or Path("(没找到)")),
        ("Clash Verge profiles/", (find_verge_dir() or Path(".")) / "profiles"),
    ]
    for label, d in targets:
        if not d or not d.exists():
            if label == "同级新建目录":
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    print(f"  {label:<24} [建不了]  {d}  ({type(e).__name__})")
                    continue
            else:
                print(f"  {label:<24} 跳过（目录不存在: {d}）")
                continue
        # 文件名带随机后缀, 不用 pid —— pid 可预测, 而 Windows 上 os.link
        # 不需要管理员权限: 本机攻击者可以预置一个指向任意文件的硬链接,
        # 我们 write_text 就把那个文件覆盖了。
        f = d / f".freevpn-diag-{secrets.token_hex(8)}"
        try:
            if f.exists() or f.is_symlink():
                print(f"  {label:<24} [跳过]  同名文件已存在（可能是硬链接攻击）")
                continue
            f.write_text("x", encoding="utf-8")
            f.unlink(missing_ok=True)
            print(f"  {label:<24} [可以写]  {d}")
        except Exception as e:
            print(f"  {label:<24} [写不了]  {d}")
            print(f"      {type(e).__name__}: {e}")

    print()
    print("  同一个目录下读呢:")
    vd = find_verge_dir()
    if vd:
        for name in ("profiles.yaml", "singleton-instance.json", "verge.yaml"):
            p = vd / name
            try:
                p.read_bytes()
                print(f"    [能读] {name}")
            except Exception as e:
                print(f"    [读不了] {name}: {type(e).__name__}: {e}")
    print()
    _conf = sec.write_confined()
    if _conf:
        print("  >>> 判定: 本程序被限制只能写自己附近")
        print("      " + _conf.replace("\n", "\n      "))
        print("      解决: 把整个文件夹移到别处再跑, 例如 C:\\freeVPN\\")
        print("            (state/ 要一起带走, 否则订阅令牌会变)")
    else:
        print("  判定: 没有被限制, 能正常写系统目录")
    print("=" * 62)
    return 0


def cmd_free_port(args):
    """清掉占着端口的进程。控制台的「清端口占用」按钮走这里。"""
    port = args.port
    holders = port_holders(port)
    if not holders:
        print(f"[*] 端口 {port} 没有被占用")
        return 0
    print(f"[*] 端口 {port} 上的占用者:")
    for h in holders:
        tag = "   <== 另一份 freeVPN" if h["is_freevpn"] else ""
        print(f"    {h['name']} (PID {h['pid']}){tag}")
        if h["cmdline"]:
            print(f"        {h['cmdline'][:150]}")
    ok, bad = kill_pids([h["pid"] for h in holders])
    time.sleep(1.5)
    for pid in ok:
        print(f"    [已结束] PID {pid}")
    for pid in bad:
        print(f"    [没结束] PID {pid} —— 权限不够? 试试用管理员身份重跑本程序")
    left = port_holders(port)
    if left:
        print(f"[!] 端口 {port} 还被占着: "
              + ", ".join(f"{h['name']}({h['pid']})" for h in left))
        return 1
    print(f"[✓] 端口 {port} 已清空")
    return 0


def cmd_import(args):
    token = sec.load_or_create_token()
    sub_url = f"http://127.0.0.1:{args.port}/sub/freevpn.yaml?token={token}"

    # 首选**直接写配置**: 实测 Clash Verge 只在启动时读一次 profiles.yaml,
    # 之后不监听、退出时也不重写 —— 运行中直接写是安全的, 不需要关客户端。
    #
    # **不再退深链。** 深链会拉起第二个 clash-verge 实例, 而有些机器上它的
    # 单例机制是坏的(拿不到单例锁, os error 5), 于是用户看到一个吓人的
    # "Clash Verge could not start" 弹窗 —— 明明订阅已经写好了。
    # 直接写失败时, 给清楚的说明比再赌一次深链有用。
    if find_verge_dir():
        if inject_verge(sub_url, args.activate, restart_client=args.restart):
            print(f"\n    订阅地址: {sub_url}")
            return 0
        print("\n[!] 没能写进 Clash Verge。手动添加订阅 (订阅页 -> 新建 -> 远程):")
        print(f"       {sub_url}")
        print(f"\n    订阅地址: {sub_url}")
        return 1

    if args.inject:
        return 1

    clients = detect_clients()
    if not clients:
        print("[!] 没检测到支持一键导入的客户端 (clash:// / mihomo:// / flclash://)")
        print("    手动把这个地址填进客户端:")
        print(f"\n{sub_url}\n")
        return 1

    print("[*] 检测到以下客户端:")
    for scheme, cmd in clients:
        print(f"    {scheme}://  ->  {cmd}")
    scheme, cmd = clients[0]
    link = import_link(scheme, sub_url)
    exe = Path(cmd).name

    print(f"\n[*] 触发 {scheme}:// 导入流程 ...")
    ok, why = launch_deeplink(link, exe)
    print(f"    {why}")

    if ok:
        print("[*] 客户端会弹窗确认, 点「导入」即可")
        print("    导入后它是一个带自动更新的远程订阅, 池子刷新会自动同步")

    if not ok:
        print("\n[!] 深链也没成功。手动添加订阅 (远程订阅 / 导入 URL), 填:")
        print(f"       {sub_url}")
        print("\n    如果客户端弹了报错窗 (常见是 os error 5 / 拒绝访问),")
        print("    那是客户端自己起不来 —— 跟导入逻辑无关。")

    print(f"\n    订阅地址: {sub_url}")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# 本地订阅服务
# --------------------------------------------------------------------------
PAGE = """<!doctype html><meta charset=utf-8><title>freeVPN</title>
<style>
body{{background:#0e1116;color:#d7dde5;font:14px/1.6 ui-monospace,Consolas,monospace;margin:0;padding:28px}}
h1{{font-size:18px;margin:0 0 4px;color:#7ee787}}
.sub{{color:#8b949e;margin-bottom:18px}}
a{{color:#79c0ff;text-decoration:none}}a:hover{{text-decoration:underline}}
table{{border-collapse:collapse;margin:10px 0 22px;width:100%;max-width:880px}}
td,th{{border-bottom:1px solid #21262d;padding:5px 10px;text-align:left}}
th{{color:#8b949e;font-weight:400}}
.k{{color:#7ee787}}.w{{color:#ffa657}}
.box{{border:1px solid #21262d;border-radius:6px;padding:12px 16px;margin:14px 0;max-width:880px;background:#161b22}}
code{{color:#ffa657}}
input{{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#7ee787;
font:12px ui-monospace,Consolas,monospace;padding:7px 9px;border-radius:5px;margin:3px 0 11px}}
.lbl{{color:#8b949e;font-size:12px}}
.btn{{display:inline-block;background:#238636;color:#fff;text-decoration:none;
padding:9px 18px;border-radius:6px;font-weight:600;margin:6px 0 4px}}
.btn:hover{{background:#2ea043}}
</style>
<h1>freeVPN</h1>
<div class=sub>{generated}</div>
<div class=box>
<b>一键导入</b> —— 点一下调起客户端, 弹窗里确认即可<br>
<a class=btn href="{import_href}">导入到 Clash Verge / Clash Party</a>
<span class=lbl>导入后它是一个带自动更新的远程订阅, 池子每轮刷新都会同步过去。</span>
<br><br>
<b>或手动填地址</b> —— 点一下输入框会自动全选, 再 Ctrl+C<br>
<span class=lbl>Clash / Mihomo / Clash Verge / ClashX</span>
<input readonly value="http://127.0.0.1:{port}/sub/freevpn.yaml?token={token}">
<span class=lbl>小火箭 / v2rayN / v2rayNG / Karing</span>
<input readonly value="http://127.0.0.1:{port}/sub/freevpn.txt?token={token}">
<span class=lbl>分区订阅 (把 hk 换成 jp / us / sg / de ...)</span>
<input readonly value="http://127.0.0.1:{port}/sub/hk.yaml?token={token}">
<span class=lbl>状态页</span>
<input readonly value="http://127.0.0.1:{port}/?token={token}">
</div>
<script nonce="{nonce}">
document.querySelectorAll("input[readonly]").forEach(function (el) {{
  el.addEventListener("click", function () {{ el.select(); }});
}});
</script>
<table><tr><th>指标</th><th>数值</th></tr>
<tr><td>源可用</td><td class=k>{sok} / {stot}</td></tr>
<tr><td>去重后</td><td>{dedupe}</td></tr>
<tr><td>安全审计 · 拦截</td><td class=w>{blocked}</td></tr>
<tr><td>安全审计 · 告警</td><td class=w>{warned}</td></tr>
<tr><td>L1 TCP 存活</td><td>{l1}</td></tr>
<tr><td>L2 内核实测可出网</td><td class=k>{l2}</td></tr>
<tr><td>入池节点</td><td class=k>{final}</td></tr>
</table>
<b>审计拦截原因</b>
<table><tr><th>原因</th><th>次数</th></tr>{reasons}</table>
<b>地区分布</b>
<table><tr><th>地区</th><th>节点数</th></tr>{regions}</table>
<b>最快 20 个</b>
<table><tr><th>#</th><th>节点</th><th>地区</th><th>协议</th><th>TCP</th><th>真实</th></tr>{fast}</table>
</body>"""


def render_page(report: dict, port: int, token: str, import_href: str = "",
                nonce: str = "") -> str:
    """渲染状态页。

    **所有来自产物的字符串一律 html.escape**。节点名完全来自不可信的公开
    订阅源, 攻击者可以把它设成 `<img src=x onerror=...>` —— 实测未转义时
    6/6 payload 原样进了响应体, 用户一打开状态页就执行任意 JS。页面另外带
    nonce CSP 兜底: 注入的 <script> 没有 nonce, 浏览器直接拒绝执行。
    """
    def esc(x) -> str:
        return html.escape(str(x), quote=True)

    reg_rows = "".join(
        f"<tr><td>{esc(region_label(k)[1])} ({esc(k)})</td><td>{esc(v)}</td></tr>"
        for k, v in list(report.get("regions", {}).items())[:24])
    fast_rows = "".join(
        f"<tr><td>{i}</td><td>{esc(f.get('name'))}</td><td>{esc(f.get('region'))}</td>"
        f"<td>{esc(f.get('type'))}</td>"
        f"<td>{esc(f.get('tcp') or '-')}</td>"
        f"<td class=k>{esc(f.get('real') or '-')}</td></tr>"
        for i, f in enumerate(report.get("fastest", [])[:20], 1))
    audit = report.get("audit") or {}
    reason_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in list((audit.get("reasons") or {}).items())[:12]) or \
        "<tr><td colspan=2>无</td></tr>"
    return PAGE.format(
        generated=esc(report.get("generated_at", "?")), port=port,
        token=esc(token), nonce=esc(nonce), import_href=esc(import_href),
        sok=esc(report.get("sources_ok", 0)), stot=esc(report.get("sources_total", 0)),
        dedupe=esc(report.get("after_dedupe", 0)), l1=esc(report.get("after_l1", 0)),
        l2=esc(report.get("after_l2") or 0), final=esc(report.get("final", 0)),
        blocked=esc(audit.get("blocked", 0)), warned=esc(audit.get("warned", 0)),
        regions=reg_rows, fast=fast_rows, reasons=reason_rows)


def make_handler(port: int, token: str, import_href: str = ""):
    class H(BaseHTTPRequestHandler):
        # 不暴露服务指纹
        server_version = ""
        sys_version = ""
        # 单连接超时。BaseHTTPRequestHandler 默认没有超时, 一条"只发半行请求、
        # 永不发完"的连接会无限期占住一个线程 —— ThreadingHTTPServer 每连接
        # 一个线程, 没有上限时资源会随连接数线性增长。
        timeout = 15

        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str, code: int = 200, head: bool = False,
                  extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # 刻意不发 CORS 头 —— 浏览器里任意网页都不该能读到本机订阅
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _deny(self, code: int, msg: str, head: bool = False):
            self._send((msg + "\n").encode("utf-8"), "text/plain; charset=utf-8", code, head)

        @staticmethod
        def _clean(s) -> str:
            """日志字段清洗: 控制字符与 Unicode 行分隔符会破坏日志结构, 让人能
            往 access.log 里插伪造行(实测 Host 头 obs-fold 可行)。"""
            return re.sub("[\x00-\x1f\x7f\x85\u2028\u2029]", "?", str(s if s is not None else ""))

        def _log(self, code: int, path: str, note: str = ""):
            """记一行访问日志。客户端报"导入失败"时全靠它还原现场。

            令牌必须脱敏 —— 日志不该成为密钥的第二个落盘点。
            之前这里写的是原始 self.path, 生产日志里 146/170 行都含完整令牌。

            脱敏必须**按值替换**, 不能只按参数名替换。实测按名字替换时,
            22 个投递形式里有 14 个把完整令牌写进了日志:

              · 路径段 /t/<token>/freevpn.yaml  (正则只管 query)
              · ?TOKEN= / ?Token=               (正则大小写敏感)
              · /sub/freevpn.yaml;token=<token> (只认 ? 和 &)
              · 令牌放在 Host 头 / User-Agent   (这两个字段也进日志)
              · %3Ftoken%3D<token>              (编码形式)

            所以: 把令牌本身从**每个字段**里抹掉, 再顺手按参数名兜一层。
            """
            def scrub(s) -> str:
                s = str(s or "")
                if token:
                    s = s.replace(token, "***")
                    # URL 编码后的形式也抹掉
                    s = s.replace(urllib.parse.quote(token, safe=""), "***")
                return s

            try:
                if ACCESS_LOG.exists() and ACCESS_LOG.stat().st_size > 1_000_000:
                    # 归档而不是删除: 删掉就没法回溯"谁在什么时候拉过订阅",
                    # 而且外部随便发点噪声就能触发清空(实测 1.21MB/12904 行
                    # 在一次请求后变成 94 字节/1 行)。
                    try:
                        ACCESS_LOG.replace(ACCESS_LOG.with_name("access.log.1"))
                    except Exception:
                        ACCESS_LOG.unlink(missing_ok=True)
                safe = scrub(path)
                safe = re.sub(r"([?&;](?:token|t)=)[^&\s]*", r"\1***", safe,
                              flags=re.I)
                with open(ACCESS_LOG, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}\t{self.command}\t{code}\t"
                            f"{self._clean(safe)}\t"
                            f"host={self._clean(scrub(self.headers.get('Host')))}\t"
                            f"ua={self._clean(scrub((self.headers.get('User-Agent') or '')[:70]))}\t"
                            f"{self._clean(scrub(note))}\n")
            except Exception:
                pass

        def do_HEAD(self):
            # 部分客户端会先发 HEAD 探测。不实现的话 BaseHTTPRequestHandler 直接回 501,
            # 客户端就把订阅地址判成不可用 —— 表现为"添加订阅失败"。
            self._route(head=True)

        def do_GET(self):
            self._route(head=False)

        def _route(self, head: bool):
            raw_path = self.path
            # ① Host 校验: 挡 DNS rebinding
            #    恶意网页可把某域名解析到 127.0.0.1, 再让浏览器去读本机订阅服务
            if not sec.host_ok(self.headers.get("Host"), port):
                self._log(403, raw_path, "forbidden host")
                return self._deny(403, "forbidden host", head)

            u = urllib.parse.urlparse(raw_path)
            qs = urllib.parse.parse_qs(u.query)
            # 路径必须解码 —— 有的客户端会把 pool.yaml 编码成 pool%2Eyaml,
            # 不解码就会被当成一个不存在的文件名, 直接回 404
            path = urllib.parse.unquote(u.path)

            # ② 令牌校验。四种形式都收, 因为不同客户端塞令牌的地方不一样:
            #    ?token=xxx / ?t=xxx / Authorization: Bearer xxx / 路径段 /t/<token>/<file>
            provided = (qs.get("token") or qs.get("t") or [None])[0]
            if not provided:
                auth = self.headers.get("Authorization") or ""
                if auth.lower().startswith("bearer "):
                    provided = auth[7:].strip()
            parts = [p for p in path.split("/") if p]
            if not provided and len(parts) >= 2 and parts[0] == "t":
                provided = parts[1]
                path = "/sub/" + "/".join(parts[2:])
            if not sec.token_ok(provided, token):
                self._log(401, raw_path, "token required")
                return self._deny(401, "token required", head)

            # ③ 路由。根路径下的订阅名也认, 客户端可能把 /sub/ 前缀吃掉
            if path in ("/", "/index.html"):
                try:
                    rep = json.loads((OUT / "report.json").read_text(encoding="utf-8"))
                except Exception:
                    rep = {}
                # nonce CSP: 页面自己的脚本带 nonce, 注入进来的 <script> 没有,
                # 浏览器直接拒绝执行 —— 转义之外的第二道防线
                nonce = secrets.token_urlsafe(16)
                page = render_page(rep, port, token, import_href, nonce)
                self._log(200, raw_path, "status page")
                return self._send(
                    page.encode("utf-8"), "text/html; charset=utf-8", 200, head,
                    {"Content-Security-Policy":
                     f"default-src 'none'; style-src 'unsafe-inline'; "
                     f"script-src 'nonce-{nonce}'; base-uri 'none'; "
                     f"form-action 'none'; frame-ancestors 'none'"})
            if path == "/report.json":
                try:
                    body = (OUT / "report.json").read_bytes()
                except Exception:
                    self._log(404, raw_path, "no report")
                    return self._deny(404, "not found", head)
                self._log(200, raw_path, "report")
                return self._send(body, "application/json", 200, head)

            fn = None
            if path.startswith("/sub/"):
                fn = path[len("/sub/"):]
            elif re.fullmatch(r"/[\w.\-]+", path):
                fn = path[1:]  # 兼容 /freevpn.yaml 这种不带 /sub/ 的写法
            if fn is not None:
                f = self._resolve_sub(fn)
                if f is None:
                    self._log(404, raw_path, f"no such sub: {fn!r}")
                    return self._deny(404, "not found", head)
                ctype = ("text/yaml; charset=utf-8" if f.suffix.lower() in (".yaml", ".yml")
                         else "text/plain; charset=utf-8")
                self._log(200, raw_path, f"served {f.name}")
                return self._send(f.read_bytes(), ctype, 200, head)

            self._log(404, raw_path, "no route")
            return self._deny(404, "not found", head)

        @staticmethod
        def _resolve_sub(fn: str):
            """在 out/ 里定位订阅文件, 容忍扩展名与大小写的差异。

            不同客户端会改写扩展名(.yml/.yaml)甚至大小写, 一律按 404 处理
            会让用户完全摸不着头脑。
            """
            if not fn or "/" in fn or "\\" in fn or ".." in fn or fn.startswith("."):
                return None
            base = OUT.resolve()
            stem = fn.rsplit(".", 1)[0] if "." in fn else fn
            # 兼容旧名字: 产物从 pool.* 改成了 freevpn.*, 但已经导入过的客户端
            # 地址还是 /sub/pool.yaml —— 不改名映射的话它们会 404。
            if stem.lower() == "pool":
                stem = "freevpn"
            cands = [fn, f"{stem}.yaml", f"{stem}.yml"]
            for c in cands:
                p = OUT / c
                if p.is_file() and str(p.resolve()).startswith(str(base)):
                    return p.resolve()
            low = fn.lower()
            for p in OUT.iterdir():
                if p.is_file() and (p.name.lower() == low
                                    or p.stem.lower() == stem.lower()):
                    return p.resolve()
            return None
    return H


class PoolServer(ThreadingHTTPServer):
    """订阅服务。

    必须关掉 allow_reuse_address: Windows 上 SO_REUSEADDR 等价于 Linux 的
    SO_REUSEPORT, 允许两个进程同时绑同一端口。后果是旧实例继续接请求、
    新实例形同不存在, 改了代码却看不到效果, 排查起来极其痛苦(实测踩过)。
    关掉之后重复启动会直接报"地址已占用", 一眼就能看出来。
    """
    allow_reuse_address = False
    daemon_threads = True


def _port_pids_netstat(port: int) -> list[int]:
    """netstat 路线。拿不到就返回空, 由调用方试下一条路。"""
    pids: list[int] = []
    r = subprocess.run(
        ["netstat", "-ano", "-p", "TCP"],
        capture_output=True, text=True, timeout=15,
        encoding=sec.console_encoding(), errors="replace",
        creationflags=sec.hidden_flags())
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        # 形如:  TCP  127.0.0.1:8787  0.0.0.0:0  LISTENING  1480
        # 端口必须**精确**比对。原来写的是 `f":{port}" in parts[1]`,
        # 那是子串匹配 —— port_holders(878) 会命中 8787,
        # port_holders(80) 会命中 8080, 而 port_holders(1) 会命中任何
        # 地址里含 ":1" 的监听者(实测命中 services.exe 和 System)。
        # 配上 free_port 的 kill, 那就是"结束任意进程"的原语。
        if len(parts) < 5 or parts[3] != "LISTENING":
            continue
        addr = parts[1]
        _host, sep, tail = addr.rpartition(":")
        if not sep or not tail.isdigit():
            continue
        if int(tail) != port:
            continue
        if parts[4].isdigit() and int(parts[4]) not in pids:
            pids.append(int(parts[4]))
    return pids


def _port_pids_powershell(port: int) -> list[int]:
    """Get-NetTCPConnection 路线 —— netstat 拿不到时的回退。

    为什么需要: netstat 会被安全软件拦、也可能输出格式不标准(不同语言/版本)。
    而这条链路正好是 GUI 的"点了没反应"重灾区 —— 查不到占用者时界面只能写
    "可能刚好释放了", 用户完全不知道该干嘛。
    """
    ps = (f"Get-NetTCPConnection -LocalPort {int(port)} -State Listen "
          f"-ErrorAction SilentlyContinue | "
          f"Select-Object -ExpandProperty OwningProcess")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=25,
        encoding=sec.console_encoding(), errors="replace",
        creationflags=sec.hidden_flags())
    out = []
    for tok in (r.stdout or "").split():
        if tok.strip().isdigit() and int(tok) not in out:
            out.append(int(tok))
    return out


def port_holders(port: int) -> list[dict]:
    """列出占着这个端口的进程: [{pid, name, cmdline, is_freevpn}]。

    控制台要能"一键清掉占用者", 所以这里返回结构化数据, 不只是给人看的文字。

    两条路取并集: netstat 和 Get-NetTCPConnection 各有各的失效场景(安全软件
    拦截、输出格式差异), 单靠一条会让界面在"端口确实被占"时显示"查不到占用者"。
    """
    pids: list[int] = []
    for finder in (_port_pids_netstat, _port_pids_powershell):
        try:
            for pid in finder(port):
                if pid not in pids:
                    pids.append(pid)
        except Exception:
            continue          # 这条路不行就换下一条, 别把整件事吞掉

    out: list[dict] = []
    for pid in pids:
        name, cmdline = "", ""
        # 优先 wmic: 一次拿到名字**和**命令行。单独用 tasklist 有时会回
        # 「没有运行的任务匹配指定标准」(进程属于别的用户), 连名字都没有。
        try:
            c = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}",
                 "get", "Name,CommandLine", "/value"],
                capture_output=True, text=True, timeout=15,
                encoding=sec.console_encoding(), errors="replace",
                creationflags=sec.hidden_flags())
            for ln in (c.stdout or "").splitlines():
                ln = ln.strip()
                if ln.startswith("Name="):
                    name = ln.split("=", 1)[1].strip()
                elif ln.startswith("CommandLine="):
                    cmdline = ln.split("=", 1)[1].strip()
        except Exception:
            pass
        if not name:
            try:
                r2 = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=15,
                    encoding=sec.console_encoding(), errors="replace",
                    creationflags=sec.hidden_flags())
                name = (r2.stdout or "").split('","')[0].strip('"') or "?"
            except Exception:
                name = "?"
        if "没有运行的任务" in name or "No tasks" in name:
            name = "?"
        low = (name + " " + cmdline).lower()
        out.append({"pid": pid, "name": name or "?",
                    "cmdline": cmdline,
                    "is_freevpn": "freevpn" in low})
    return out


def kill_pids(pids: list[int], tree: bool = False) -> tuple[list[int], list[int]]:
    """强杀一批 PID。返回 (成功, 失败)。

    **默认不带 `/T`。** `/T` 会连同目标进程的整棵子进程树一起结束 ——
    实测: 一个监听端口的进程自己拉起的、与端口毫无关系的子进程,
    也会被一并杀掉。用户以为只是"清掉占端口的那个进程", 实际影响面更大。
    确实需要树杀时显式传 tree=True。
    """
    ok, bad = [], []
    for pid in pids:
        cmd = ["taskkill", "/F"] + (["/T"] if tree else []) + ["/PID", str(pid)]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20,
                encoding=sec.console_encoding(), errors="replace",
                creationflags=sec.hidden_flags())
            (ok if r.returncode == 0 else bad).append(pid)
        except Exception:
            bad.append(pid)
    return ok, bad


def free_port(port: int) -> tuple[list[dict], list[int], list[int]]:
    """清掉占着这个端口的进程。

    返回 (占用者列表, 已结束的 PID, 没结束的 PID)。
    只动这个端口的占用者 —— 不要像以前那样 `taskkill /F /IM python.exe`,
    那会把机器上所有 Python 进程一起杀掉, 包括用户自己正在跑的东西。
    """
    holders = port_holders(port)
    if not holders:
        return [], [], []
    pids = [h["pid"] for h in holders]
    ok, bad = kill_pids(pids)
    if ok:
        time.sleep(1.5)          # 等内核把监听套接字真正释放掉
    return holders, ok, bad


def who_holds_port(port: int) -> str:
    """查出谁占着这个端口, 返回一句人能看懂的话。"""
    holders = port_holders(port)
    if not holders:
        return "查不到是哪个进程（可能刚好释放了）"
    out = []
    for h in holders:
        tag = "   <== 另一份 freeVPN" if h["is_freevpn"] else ""
        out.append(f"{h['name']} (PID {h['pid']}){tag}")
        if h["cmdline"]:
            out.append(f"        命令行: {h['cmdline'][:150]}")
    return "\n      ".join(out)


def serve(port: int, block: bool = True):
    token = sec.load_or_create_token()
    sub_url = f"http://127.0.0.1:{port}/sub/freevpn.yaml?token={token}"
    clients = detect_clients()
    import_href = import_link(clients[0][0], sub_url) if clients else ""
    try:
        srv = PoolServer(("127.0.0.1", port), make_handler(port, token, import_href))
    except OSError as e:
        holder = who_holds_port(port)
        print(f"\n[SRV] 端口 {port} 已被占用 —— 订阅服务起不来。")
        print(f"      占用者: {holder}")
        if "freeVPN" in holder:
            print("      ^^ 这是**另一份 freeVPN**。同一个端口只能有一份在跑,")
            print("         而且源码版和打包版各有自己的 state/token.txt,")
            print("         令牌不同 —— 客户端里那个订阅地址会 401。")
            print("         留一份就好: 把不用的那个关掉。")
        # 只结束占用者, 不要一杆子打翻所有 python 进程
        print(f"      结束它:  taskkill /F /PID <上面的 PID>")
        print(f"      或者换端口:  --port {port + 1}")
        if sec.is_frozen():
            print(f"      (本程序: {Path(sys.executable).name}  {sec.app_root()})")
        print(f"      原始错误: {e}")
        raise SystemExit(1)
    urls = [
        ("Clash / Mihomo / Clash Verge / ClashX",
         f"http://127.0.0.1:{port}/sub/freevpn.yaml?token={token}"),
        ("小火箭 / v2rayN / v2rayNG / Karing",
         f"http://127.0.0.1:{port}/sub/freevpn.txt?token={token}"),
        ("状态页 (浏览器打开)",
         f"http://127.0.0.1:{port}/?token={token}"),
    ]

    def _mask(u: str) -> str:
        """把 URL 里的令牌换成掩码。

        **stdout 会被重定向进 daemon.log**, 而日志的 ACL 是
        `Authenticated Users:(M)` —— 任何本机用户可读。直接打印带令牌的
        完整地址等于把订阅密钥写进一个宽松权限的文件, 而 token.txt 自己的
        ACL 收紧就被这样绕过去了(实测 daemon.log 里 45 行含完整令牌)。

        屏幕上仍然显示完整地址(用户要用), 需要复制的完整地址也仍然写进
        `订阅地址.txt` —— 那个文件的权限是收紧过的。
        """
        return u.replace(token, token[:6] + "…" + token[-4:]) if token else u

    print()
    print("=" * 66)
    if clients:
        print(f"  一键导入: 打开状态页点按钮, 或跑  python pool.py import")
        print(f"  (检测到 {', '.join(s for s, _ in clients)})")
        print("-" * 66)
    print("  或手动复制地址 —— 整行复制, 不要带前面的说明文字")
    print("  (客户端只看开头是不是 http://, 带上标签就会报'无效的订阅链接')")
    print("=" * 66)
    for label, u in urls:
        print(f"\n  {label}")
        print(_mask(u))
    print()
    try:
        ADDR_FILE.write_text("\n".join(u for _l, u in urls) + "\n", encoding="utf-8")
        # 这个文件里就是令牌明文, 权限必须一起收紧(chmod 在 Windows 上不动 ACL)
        sec.tighten_file_perms(ADDR_FILE)
        print(f"  完整地址已写入: {ADDR_FILE}")
        print("  (上面的地址做了掩码, 免得落进日志; 要复制请打开这个文件)")
    except Exception:
        pass
    print("=" * 66)
    if block:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[SRV] 停止")
    return srv


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def set_progress(op: str, phase: str, done: int = 0, total: int = 0,
                 note: str = "") -> None:
    """把当前进度写到一个文件, 供控制台读取。

    为什么落盘而不是进程间通信: 扫描是**子进程**在跑, 常驻和 GUI 都只是旁观者。
    写文件是最省事的共享方式, 而且 GUI 没开、崩了都不影响扫描本身。
    """
    now = time.time()
    started = now
    try:
        # 同一个操作要沿用最初的开始时刻, 否则界面上"已用时"每写一次就归零
        old = json.loads(PROGRESS.read_text(encoding="utf-8"))
        if old.get("op") == op and old.get("started"):
            started = old["started"]
    except Exception:
        pass
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        PROGRESS.write_text(json.dumps({
            "op": op, "phase": phase, "done": done, "total": total,
            "note": note, "ts": now, "started": started, "pid": os.getpid(),
        }, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def clear_progress() -> None:
    try:
        PROGRESS.unlink(missing_ok=True)
    except Exception:
        pass


def run_cycle(args) -> dict:
    print(f"\n{'='*66}\n[{datetime.now():%H:%M:%S}] 开始刷新 freeVPN\n{'='*66}")
    marks: list[tuple[str, float]] = []
    _t = [time.time()]

    def lap(label: str):
        now = time.time()
        marks.append((label, now - _t[0]))
        _t[0] = now

    def dump_timing():
        if not marks:
            return
        total = sum(d for _l, d in marks)
        print("[耗时] " + "  ".join(f"{l} {d:.1f}s" for l, d in marks)
              + f"  | 合计 {total:.1f}s")

    stats: dict = {}
    audit = None
    l1 = None
    dedupe_n: int | None = None      # 去重后的唯一节点数, 供 report.json 用
    if getattr(args, "reuse_l1", False):
        l1 = load_l1()
        if l1:
            print(f"[L1] 复用上次结果: {len(l1)} 个存活节点 (跳过拉源与 TCP 探活)")
            l1, audit = sec.audit_pool(l1)
            print(f"[安全] 缓存复检: {sec.summarize(audit)}")
            # 复用缓存时本轮没有拉源, 沿用上一次报告的源统计,
            # 否则状态页会显示"源可用 0/0", 看着像坏了
            try:
                prev = json.loads((OUT / "report.json").read_text(encoding="utf-8"))
                stats = prev.get("sources") or {}
            except Exception:
                stats = {}
    if l1 is None:
        set_progress("完整扫描", "拉源", 0, 0, f"{len(load_sources())} 个源")
        raw, stats = collect()
        lap("拉源")
        if not raw:
            print("[!] 本轮没拉到任何节点, 保留上一次产物")
            clear_progress()
            return {}
        set_progress("完整扫描", "解析去重", 0, 0, f"原始 {len(raw)} 条")
        nodes = dedupe(raw)
        lap("解析+去重")
        print(f"[*] 去重: {len(raw)} -> {len(nodes)} 唯一节点")
        dedupe_n = len(nodes)          # 供 report.json 的 after_dedupe 用
        set_progress("完整扫描", "安全审计", 0, len(nodes))
        nodes, audit = sec.audit_pool(nodes)
        lap("安全审计")
        print(f"[安全] {sec.summarize(audit)}")
        if not nodes:
            print("[!] 所有节点均未通过安全审计")
            clear_progress()
            return {}
        l1_hist = load_l1_hist()
        l1 = probe_tcp(nodes, timeout=args.timeout, concurrency=args.concurrency,
                       hist=l1_hist,
                       ttl=getattr(args, "neg_ttl", 5400),
                       min_fails=getattr(args, "neg_l1_fails", 2),
                       op="完整扫描")
        save_l1_hist(l1_hist)
        lap("L1 TCP 探活")
        if l1:
            save_l1(l1)
    if not l1:
        print("[!] L1 全灭, 保留上一次产物")
        clear_progress()
        return {}

    l2_count = None
    final = l1
    if not args.no_l2 and MIHOMO.exists():
        cand = diversify(rank(l1), per_subnet=getattr(args, "per_subnet", 4))[: args.l2_top]
        print(f"[L2] L1 存活 {len(l1)} 个, 网段多样化后取 {len(cand)} 个送内核实测 ...")
        set_progress("完整扫描", "L2 内核实测", 0, len(cand))
        l2_hist = load_l2_hist()
        real = probe_real(cand, timeout_ms=args.l2_timeout,
                          workers=getattr(args, "l2_workers", 192),
                          test_url=getattr(args, "test_url", TEST_URL),
                          target=getattr(args, "l2_target", 0),
                          budget=getattr(args, "l2_budget", 0),
                          hist=l2_hist,
                          ttl=getattr(args, "neg_ttl", 5400),
                          # 默认关闭。实测 L2 失败过的节点仍有 1.7% 能出网, 而整体
                          # 通过率是 2.2% —— 差得太少, 说明"L2 失败过"没有预测力,
                          # 开了只是按比例丢节点换时间。L1 那个缓存则完全不同
                          # (跳过组 3.0% vs 对照组 92.2%, 差 30 倍), 那个是真信号。
                          min_fails=getattr(args, "neg_l2_fails", 0),
                          op="完整扫描")
        save_l2_hist(l2_hist)
        lap("L2 内核实测")
        if real:
            l2_count = len(real)
            final = rank(real)
        else:
            # L2 一个都没出(内核起不来 / 配置全被拒 / 超预算)。
            #
            # **不能拿 L1 的结果顶替。** L1 只是"TCP 握手能通", 实测 L1 存活里
            # 只有 ~2.5% 真能出网(某轮: L1 存活 3342 -> L2 可用 64)。
            # 拿 L1 当池子, 用户会看到一个"有 3342 个节点"的订阅, 然后一个都连不上
            # —— 比空池子更糟, 因为看起来是好的。
            #
            # 正确做法: 保留上一轮产物, 并明确说明。订阅宁可暂时空着,
            # 也不要给一堆连不上的节点。
            print("[L2] 内核实测无结果 —— 保留上一轮产物, 不拿 L1 结果顶替")
            print("     (L1 只验证了 TCP 可达, 实测其中只有百分之几真能出网;")
            print("      把它当池子会得到一个'看起来有几千节点但全连不上'的订阅)")
            clear_progress()
            return {}
    else:
        # 用户显式 --no-l2, 或者机器上根本没有 mihomo 内核。
        # 这种情况只能用 L1 结果, 但必须说清楚池子质量差得多。
        #
        # QUIC 节点要单独摘掉: 它们连 TCP 探测都没做(见 UDP_TYPES), 一个
        # 字节的验证都没有, 混进"L1 存活"里就是纯编造。
        verified = [n for n in l1 if n.get("_tcp") is not None]
        n_udp = len(l1) - len(verified)
        final = rank(verified)
        print("[!] 没有做 L2 内核实测 —— 池子里是 L1 的结果")
        print("    L1 只验证 TCP 可达, 实测其中只有百分之几真能出网。")
        if n_udp:
            print(f"    另有 {n_udp} 个 QUIC(hysteria/tuic) 节点跳过 L1 且未经"
                  f"任何验证, 已排除")
        if not MIHOMO.exists():
            print(f"    原因: 找不到内核 {MIHOMO}")
        else:
            print("    原因: 指定了 --no-l2")

    set_progress("完整扫描", "写产物", 0, 0)
    hist = load_cache()
    save_cache(final, hist)
    save_pool(final)
    report = write_outputs(final, stats, len(l1), l2_count, audit,
                           dedupe_total=dedupe_n)
    lap("写产物")
    clear_progress()
    print(f"[✓] 入池 {report['final']} 个节点, 覆盖 {len(report['regions'])} 个地区")
    print(f"    产物: {OUT / 'freevpn.yaml'}")
    dump_timing()
    return report


def main():
    ap = argparse.ArgumentParser(
        description=f"freeVPN · 多源聚合 + 双层探活  (v{ver.__version__})")
    ap.add_argument("--version", action="version",
                    version=ver.version_string())
    sub = ap.add_subparsers(dest="cmd")

    def add_run_args(sp):
        sp.add_argument("--no-l2", action="store_true", help="跳过内核真实测速")
        sp.add_argument("--l2-top", type=int, default=3000, help="送内核实测的节点数上限")
        sp.add_argument("--l2-timeout", type=int, default=3000, help="内核测速超时(ms)")
        sp.add_argument("--l2-workers", type=int, default=192, help="内核测速并发")
        sp.add_argument("--l2-target", type=int, default=0, help="凑够多少可用节点就停(0=不限)")
        sp.add_argument("--l2-budget", type=float, default=600, help="L2 时间预算(秒, 0=不限)")
        sp.add_argument("--per-subnet", type=int, default=4, help="同一 /24 段最多取几个节点")
        sp.add_argument("--neg-ttl", type=int, default=5400,
                        help="负缓存有效期(秒): 失败节点多久后重新给机会")
        sp.add_argument("--neg-l1-fails", type=int, default=2,
                        help="L1 连续失败几次才跳过")
        sp.add_argument("--neg-l2-fails", type=int, default=0,
                        help="L2 连续失败几次才跳过 (0=关闭)。实测 L2 失败过的节点"
                             "仍有 1.7% 能出网, 和整体通过率 2.2% 几乎一样 —— "
                             "它没有预测力, 所以默认关闭, 开了就是按比例丢节点")
        sp.add_argument("--test-url", default=TEST_URL, help="内核测速目标 URL")
        sp.add_argument("--reuse-l1", action="store_true", help="复用上次 L1 结果(调 L2 参数用)")
        sp.add_argument("--timeout", type=float, default=5.0, help="TCP 探活超时(秒)")
        sp.add_argument("--concurrency", type=int, default=500, help="TCP 并发数")

    p = sub.add_parser("fetch", help="只拉源看产出")
    p = sub.add_parser("all", help="全流程跑一轮")
    add_run_args(p)

    s = sub.add_parser("serve", help="起订阅服务")
    s.add_argument("--port", type=int, default=8787)

    i = sub.add_parser("import", help="一键导入到已装的客户端")
    i.add_argument("--port", type=int, default=8787)
    i.add_argument("--inject", action="store_true",
                   help="全自动: 直接写进 Clash Verge 配置目录(需先退出客户端)")
    i.add_argument("--activate", action="store_true",
                   help="配合 --inject, 同时把它设为当前使用中的配置")
    i.add_argument("--restart", action="store_true",
                   help="写完之后顺便重启 Clash Verge —— 它只在启动时读配置, "
                        "正在运行时新订阅要重启才看得到")

    up = sub.add_parser("update", help="从 GitHub 拉最新版本(只下载, 不自动执行)")
    up.add_argument("--check", action="store_true", help="只检查有没有新版本")
    up.add_argument("--force", action="store_true", help="版本相同也重新下载")

    d = sub.add_parser("daemon", help="常驻: 定时刷新 + 服务")
    d.add_argument("--port", type=int, default=8787)
    d.add_argument("--interval", type=int, default=30, help="完整扫描间隔(分钟)")
    d.add_argument("--fast", type=int, default=5, help="快车道复检间隔(分钟)")
    d.add_argument("--log", default="", help="输出写文件(计划任务无控制台时必需)")
    d.add_argument("--once", action="store_true", help="只跑一轮不循环")
    add_run_args(d)

    st = sub.add_parser("status", help="看一眼池子现在什么状态")
    st.add_argument("--port", type=int, default=8787)
    st.add_argument("--interval", type=int, default=30, help="完整扫描间隔(分钟)")
    st.add_argument("--fast", type=int, default=5, help="快车道间隔(分钟)")

    g = sub.add_parser("gui", help="打开桌面控制台")
    g.add_argument("--port", type=int, default=8787)

    dw = sub.add_parser("diag-write", help="诊断: 本程序能往哪些目录写")
    dw.add_argument("--port", type=int, default=8787)

    fp = sub.add_parser("free-port", help="清掉占着端口的进程(只动占用者)")
    fp.add_argument("--port", type=int, default=8787)

    q = sub.add_parser("quick", help="快车道: 只重测池内节点, 几秒完成")
    add_run_args(q)

    au = sub.add_parser("autostart", help="开机自启(注册计划任务)")
    au.add_argument("--remove", action="store_true", help="取消开机自启")
    au.add_argument("--port", type=int, default=8787)
    au.add_argument("--interval", type=int, default=30, help="完整扫描间隔(分钟)")

    # 配置文件只提供默认值, 命令行参数优先。
    # 必须同时设到**每个子解析器**上 —— argparse 的子解析器解析时会把自己那份
    # 默认值写回 namespace, 只设主解析器会被覆盖掉。
    conf = load_conf()
    _applied: dict = {}
    _unknown: list = []
    if conf:
        targets = [ap] + [a for a in ap._actions
                          if isinstance(a, argparse._SubParsersAction)
                          for a in a.choices.values()]
        known_all = {a.dest for tgt in targets for a in tgt._actions}
        for tgt in targets:
            known = {a.dest for a in tgt._actions}
            hit = {k: v for k, v in conf.items() if k in known}
            if hit:
                tgt.set_defaults(**hit)
                _applied.update(hit)
        # `_` 开头的键当注释用, 不报"不认识"; cn_* 由 configure_cn 消费, 同理
        _unknown = sorted(k for k in conf
                          if not k.startswith("_") and k not in known_all
                          and k not in CN_CONF_KEYS)

    args = ap.parse_args()

    # 国内分流设置: 必须在跑任何命令之前生效 —— 产物规则的组装读的是
    # sec.SECURITY_RULES, 它在这里被重建。
    cn_mode = sec.configure_cn(mode=conf.get("cn_mode"),
                               resolve=conf.get("cn_resolve"),
                               ipv6=conf.get("cn_ipv6"))
    if args.cmd in ("all", "quick", "daemon", "fetch"):
        print(f"[*] {sec.cn_summary()}  (cn_mode={cn_mode})")

    if _applied and args.cmd in ("daemon", "status"):
        print(f"[*] 已套用 {CONF_FILE.name}: "
              + ", ".join(f"{k}={v}" for k, v in sorted(_applied.items())))
    if _unknown:
        print(f"[!] {CONF_FILE.name} 里这些键不认识, 已忽略: {_unknown}")
    if not args.cmd:
        ap.print_help()
        return

    if args.cmd == "fetch":
        raw, stats = collect()
        nodes = dedupe(raw)
        print(f"\n[*] 合计 {len(raw)} -> 去重后 {len(nodes)} 个唯一节点")
        from collections import Counter
        c = Counter(n.get("_region") for n in nodes)
        print("[*] 地区分布:", ", ".join(f"{k}:{v}" for k, v in c.most_common(20)))
        return

    if args.cmd == "all":
        run_cycle(args)
        return

    if args.cmd == "serve":
        serve(args.port)
        return

    if args.cmd == "import":
        raise SystemExit(cmd_import(args))

    if args.cmd == "update":
        raise SystemExit(updater.run(check_only=args.check, force=args.force))

    if args.cmd == "daemon":
        # 中文提示一律由 Python 打印 —— .bat 必须是纯 ASCII, 否则 cmd.exe
        # 按 GBK 解析 UTF-8 字节会在词中间断开, 报一堆"不是内部或外部命令"
        full = max(5, args.interval)
        fast = max(1, args.fast)
        # 计划任务里没有控制台, stdout 会是 None, 什么都看不到 —— 所以支持落日志
        if args.log:
            try:
                lf = open(args.log, "a", encoding="utf-8", buffering=1)
                sys.stdout = lf
                sys.stderr = lf
            except Exception as e:
                print(f"[!] 打开日志失败: {e}")
        # 对齐时钟刻度排程, 而不是"上次跑完 + 间隔"。
        # 后者会漂移: 完整扫描本身要 4~5 分钟, 30 分钟档实际变成 35 分钟,
        # 而且每轮继续往后漂 —— 用户看到的"每 30 分钟刷新"名不副实。
        # 对齐刻度之后 30 分钟档永远在 :00/:30, 5 分钟档在 :00:05:10…, 与扫描耗时无关。
        #
        # 但**首次运行必须立刻跑一轮**: 还没任何产物时如果也去等下一个刻度,
        # 用户在 12:26 打开程序就要干等到 12:30 才有节点 —— 全新安装最长空等
        # 30 分钟, 界面上什么提示都没有, 看起来就是"用不了"。
        first_run = not (OUT / "report.json").exists()
        if first_run:
            next_full = 0.0
            next_fast = 0.0
        else:
            next_full = _next_slot(full)
            next_fast = _next_slot(fast)
        print("=" * 64)
        print(f"  {ver.__title__} v{ver.__version__} · 常驻模式")
        print(f"  完整扫描   每 {full} 分钟一次 (重新拉源 + 全量测速)")
        print(f"  快车道复检 每 {fast} 分钟一次 (只重测池内节点, 几秒完成)")
        print(f"  排程       对齐时钟刻度, 不随扫描耗时漂移")
        if first_run:
            print("  首次运行   立刻跑一轮完整扫描 (不等刻度)")
        else:
            print(f"             下次完整扫描 {_slot_str(next_full)}"
                  f"   下次快车道 {_slot_str(next_fast)}")
        print(f"  服务端口   {args.port} (仅监听回环)")
        print("  首轮要 1~3 分钟才有产物, 期间订阅是空的")
        print("  按 Ctrl+C 停止")
        _confined = sec.write_confined()
        if _confined:
            print()
            print("  " + "!" * 60)
            print("  !! 本程序被限制只能写自己附近 —— 导入客户端、开机自启都会失败")
            print("     " + _confined.replace("\n", "\n     "))
            print(f"     程序位置: {sec.app_root()}")
            print("     解决: 把整个文件夹移到别处再跑, 例如 C:\\freeVPN\\")
            print("          (state/ 要一起带走, 否则订阅令牌会变)")
            print("  " + "!" * 60)
        # 安装目录如果对本机其他用户可写, 收紧它 —— 否则别人能替换
        # freeVPN.exe / bin/mihomo.exe(会被执行), 或改 out/freevpn.yaml(订阅本身)
        if sec.is_frozen() and sec.dir_is_loose(sec.app_root()):
            print()
            print("  [!] 安装目录对本机其他用户可写 —— 正在收紧权限 ...")
            if sec.harden_install_dir(sec.app_root()):
                print("      已收紧为「当前用户 + SYSTEM」")
            else:
                print("      收紧失败(可能权限不够), 建议手动执行:")
                print(f'      icacls "{sec.app_root()}" /inheritance:r '
                      f'/grant:r "%USERNAME%:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" /T')
        print("=" * 64)
        srv = serve(args.port, block=False)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        if args.once:
            run_cycle(args)
            return
        # 写 pid 文件: 控制台(GUI)靠它判断常驻在不在跑 —— 读文件比每 2 秒起一次
        # wmic 查进程便宜得多, 而且不会在屏幕上闪控制台窗口
        pidf = STATE / "daemon.pid"
        try:
            STATE.mkdir(parents=True, exist_ok=True)
            pidf.write_text(str(os.getpid()), encoding="utf-8")
        except Exception:
            pass
        # 扫描参数透传给子进程
        passthrough = ["--l2-workers", str(args.l2_workers),
                       "--l2-timeout", str(args.l2_timeout),
                       "--test-url", args.test_url,
                       "--timeout", str(args.timeout),
                       "--concurrency", str(args.concurrency),
                       "--l2-top", str(args.l2_top),
                       "--l2-target", str(args.l2_target),
                       "--l2-budget", str(args.l2_budget),
                       "--per-subnet", str(args.per_subnet)]
        if args.no_l2:
            passthrough.append("--no-l2")
        logpath = Path(args.log) if args.log else None

        try:
            while True:
                now = time.time()
                due_full = now >= next_full
                due_fast = now >= next_fast
                if not due_full and not due_fast:
                    wait = min(next_full, next_fast) - now
                    time.sleep(max(1.0, min(wait, 60.0)))
                    continue

                if due_full:
                    tag = "完整扫描"
                elif due_fast:
                    tag = "快车道复检"
                else:
                    continue

                print(f"\n[{datetime.now():%H:%M:%S}] {tag} —— 交给子进程, 本进程继续服务订阅")
                rc = run_child((["all"] if due_full else ["quick"]) + passthrough, logpath)
                if rc != 0:
                    print(f"[!] 子进程返回码 {rc}")

                # 排程基于**本轮结束时刻**推进下一个刻度。
                # 用开始时刻的话会白白多扫一轮: 12:58 开跑、12:59:40 跑完,
                # 算出来的下一个刻度是 13:00 —— 刚扫完就又来一遍。
                # 用结束时刻仍然是刻度对齐, 该不漂移还是不漂移。
                #
                # 光换结束时刻还不够: 12:59:40 的下一个刻度依然是 13:00, 只隔
                # 20 秒。所以再加一条 —— 离得太近就顺延一格, 保证两轮之间至少
                # 隔开三分之一个周期。
                done_at = time.time()

                def _schedule(interval_min: int) -> float:
                    nxt = _next_slot(interval_min, done_at)
                    if nxt - done_at < interval_min * 60 * 0.34:
                        nxt = _next_slot(interval_min, nxt)
                    return nxt

                if due_full:
                    next_full = _schedule(full)
                    # 完整扫描刚做完, 快车道重新起算
                    next_fast = _schedule(fast)
                else:
                    next_fast = _schedule(fast)

                print(f"[*] 下次完整扫描 {_slot_str(next_full)}   下次快车道 {_slot_str(next_fast)}")
        finally:
            # 正常退出/被 Ctrl+C 都要清掉, 否则控制台会一直显示"常驻运行中"
            try:
                pidf.unlink(missing_ok=True)
            except Exception:
                pass

    if args.cmd == "quick":
        raise SystemExit(0 if fast_refresh(args) else 1)

    if args.cmd == "status":
        raise SystemExit(cmd_status(args))

    if args.cmd == "diag-write":
        raise SystemExit(cmd_diag_write(args))

    if args.cmd == "free-port":
        raise SystemExit(cmd_free_port(args))

    if args.cmd == "gui":
        # 桌面控制台单独一个文件, 免得 pool.py 继续膨胀
        sys.path.insert(0, str(ROOT))
        import gui  # noqa: E402
        raise SystemExit(gui.main(args.port))

    if args.cmd == "autostart":
        raise SystemExit(cmd_autostart(args))


if __name__ == "__main__":
    main()
