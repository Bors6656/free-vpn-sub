#!/usr/bin/env python3
"""
Free VPN Sub Generator
拉取多个公开订阅/代理源，去重后输出标准 clash.yaml。
每小时自动触发，无请求数限制（走 GitHub raw CDN）。
"""
import os, re, sys, base64, json, urllib.request, urllib.error
from datetime import datetime
from collections import OrderedDict

REQ_TIMEOUT = 15
MAX_PROXIES = 120

# 可自由增删源。格式: (type, url)
#  type: "clash" | "base64" | "text"
SOURCES = [
    # 常见公益聚合源（保留相对稳定的历史源，失效请自行替换）
    ("clash", "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml"),
    ("clash", "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash"),
    ("base64", "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_base64.txt"),
    ("base64", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    ("base64", "https://raw.githubusercontent.com/liujf2857/Free-Node-Sub/main/sub"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=REQ_TIMEOUT) as r:
        return r.read().decode("utf-8", errors="ignore")


def try_parse_clash(text: str):
    """处理纯 clash yaml 格式"""
    # 极简 yaml 解析：只提取 proxies 数组，避免引入外部依赖
    # 兼容标准 clash 配置
    m = re.search(r'(?m)^proxies:\s*\n(.*?)(?=\n\w|\Z)', text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    proxies = []
    # 按 "- name:" 拆分
    items = re.split(r'(?m)^\s*-\s+name:\s*', block)
    for item in items[1:]:
        # 第一行是 name 值
        name = item.splitlines()[0].strip().strip('"').strip("'")
        proxy = {"name": name}
        # 解析后续 key: value（有限缩进）
        for line in item.splitlines()[1:]:
            line = line.rstrip()
            m2 = re.match(r'^\s+([\w-]+)\s*:\s*(.+)$', line)
            if m2:
                k, v = m2.group(1), m2.group(2).strip()
                # 简单类型推断
                if v.lower() == "true":
                    v = True
                elif v.lower() == "false":
                    v = False
                else:
                    try:
                        v = int(v)
                    except ValueError:
                        v = v.strip('"').strip("'")
                proxy[k] = v
        if proxy.get("name"):
            proxies.append(proxy)
    return proxies


def decode_base64_maybe(text: str) -> str:
    text = text.strip()
    # 处理 pad 问题
    rem = len(text) % 4
    if rem:
        text += "=" * (4 - rem)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def try_parse_base64_link(link: str):
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(link[8:]))
            return {
                "name": data.get("ps", ""),
                "type": "vmess",
                "server": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id", ""),
                "alterId": int(data.get("aid", 0)),
                "network": data.get("net", "tcp"),
                "cipher": data.get("scy", "auto"),
            }
        except Exception:
            return None
    if link.startswith("ss://"):
        # SIP002: ss://base64(method:password)@server:port#name
        try:
            body, _, name = link[5:].partition("#")
            if "@" in body:
                userinfo_b64, host_port = body.rsplit("@", 1)
                userinfo = base64.b64decode(
                    userinfo_b64 + "=" * (-len(userinfo_b64) % 4)
                ).decode()
                method, pwd = userinfo.split(":", 1)
                server, port = host_port.rsplit(":", 1)
                return {
                    "name": name or server,
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": method,
                    "password": pwd,
                }
        except Exception:
            return None
    if link.startswith("trojan://"):
        m = re.match(
            r"trojan://([^@]+)@([^:/]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$", link
        )
        if m:
            pwd, server, port, params, name = m.groups()
            ps = {}
            if params:
                ps = dict(re.findall(r"([^&=]+)=([^&]*)", params))
            return {
                "name": name or ps.get("sni", server),
                "type": "trojan",
                "server": server,
                "port": int(port),
                "password": pwd,
                "sni": ps.get("sni", server),
                "udp": True,
            }
    if link.startswith("vless://"):
        # vless://uuid@server:port?params#name
        m = re.match(
            r"vless://([^@]+)@([^:/]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$", link
        )
        if m:
            uuid, server, port, params, name = m.groups()
            ps = {}
            if params:
                ps = dict(re.findall(r"([^&=]+)=([^&]*)", params))
            return {
                "name": name or ps.get("sni", server),
                "type": "vless",
                "server": server,
                "port": int(port),
                "uuid": uuid,
                "network": ps.get("type", "tcp"),
                "sni": ps.get("sni", server),
                "udp": True,
            }
    return None


def try_parse_base64(text: str):
    proxies = []
    # 先判断是否为整段 base64
    stripped = text.strip()
    decoded = ""
    # 如果肉眼像 base64（只含 A-Z a-z 0-9 + / = \n \r）
    if re.match(r"^[A-Za-z0-9+/=\s\r\n]+$", stripped) and len(stripped) > 20:
        decoded = decode_base64_maybe(stripped)
    # 逐行解析协议链接
    for line in (decoded or stripped).splitlines():
        p = try_parse_base64_link(line)
        if p:
            proxies.append(p)
    return proxies


def render_clash_yaml(proxies) -> str:
    # 字段精简保真
    essential = ["type", "server", "port", "cipher", "password", "uuid",
                 "alterId", "network", "plugin-opts", "sni", "udp"]
    out = [
        "mixed-port: 7890",
        "allow-lan: true",
        "mode: Rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "",
        "proxies:",
    ]
    names = []
    for p in proxies:
        name = p.get("name") or f"node-{len(names)+1}"
        names.append(name)
        out.append(f'  - name: "{name}"')
        for k in essential:
            if k in p:
                v = p[k]
                if isinstance(v, str):
                    v = f"\"{v}\""
                elif isinstance(v, bool):
                    v = "true" if v else "false"
                out.append(f"    {k}: {v}")
        out.append("")

    out += [
        "proxy-groups:",
        "  - name: Proxy",
        "    type: select",
        "    proxies:",
        "      - Auto",
    ]
    out.extend([f"      - \"{n}\"" for n in names[:30]])
    out.extend([
        "  - name: Auto",
        "    type: url-test",
        "    proxies:",
    ])
    out.extend([f"      - \"{n}\"" for n in names[:30]])
    out.extend([
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "",
        "rules:",
        "  - MATCH,Proxy",
    ])
    return "\n".join(out)


def dedup(proxies):
    seen = OrderedDict()
    for p in proxies:
        key = (p.get("name", ""), str(p.get("server", "")), str(p.get("port", "")))
        if key not in seen:
            seen[key] = p
    return list(seen.values())


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(root, "dist")
    os.makedirs(out_dir, exist_ok=True)

    all_proxies = []
    for kind, url in SOURCES:
        try:
            txt = fetch(url)
            if kind == "clash":
                nodes = try_parse_clash(txt)
            elif kind == "base64":
                nodes = try_parse_base64(txt)
            else:
                nodes = try_parse_base64(txt)
            print(f"[+] {url} => {len(nodes)} nodes")
            all_proxies.extend(nodes)
        except Exception as e:
            print(f"[-] {url} error: {e}")

    all_proxies = dedup(all_proxies)
    yaml_text = render_clash_yaml(all_proxies[:MAX_PROXIES])

    out_path = os.path.join(out_dir, "clash.yaml")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(yaml_text)

    print(f"[=] saved {out_path}  total_unique={len(all_proxies)}  using={min(len(all_proxies), MAX_PROXIES)}")


if __name__ == "__main__":
    main()
