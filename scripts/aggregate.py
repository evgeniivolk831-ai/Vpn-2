import base64
import json
import os
import re
import socket
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

TARGET = 15
TARGET_RESILIENT = 10
TARGET_NORMAL = 5

SOURCES = [
    ("mehrtat-vless", "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt"),
    ("baarcuda-top100", "https://raw.githubusercontent.com/Baarcuda/vpn-configs/master/top100-vless.txt"),
    ("vovaplus-secure", "https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure-Base64/vless.txt"),
    ("au1rxx", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/vless.txt"),
    ("morpheusadam", "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/vless.txt"),
]

OUT = "output"
os.makedirs(OUT, exist_ok=True)

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "GlobalPulse/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "ignore")

def decode_payload(text):
    text = text.strip()
    direct = [x.strip() for x in text.splitlines() if x.strip().lower().startswith("vless://")]
    if direct:
        return direct
    compact = re.sub(r"\s+", "", text)
    try:
        pad = "=" * ((4 - len(compact) % 4) % 4)
        raw = base64.b64decode(compact + pad).decode("utf-8", "ignore")
        if raw and raw != text:
            return decode_payload(raw)
    except Exception:
        pass
    return []

def parse_vless(uri):
    p = urlparse(uri)
    if p.scheme.lower() != "vless" or not p.hostname or not p.port or not p.username:
        return None
    q = parse_qs(p.query)
    security = q.get("security", [""])[0].lower()
    transport = q.get("type", ["tcp"])[0].lower()
    cls = "RESILIENT" if security == "reality" else "NORMAL"
    return {
        "uri": uri,
        "host": p.hostname,
        "port": p.port,
        "uuid": p.username,
        "name": unquote(p.fragment) if p.fragment else f"{p.hostname}:{p.port}",
        "security": security,
        "transport": transport,
        "params": {k: v[0] for k, v in q.items()},
        "class": cls,
    }

def tcp_check(node):
    started = time.monotonic()
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=3.5):
            node["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            return True
    except Exception:
        return False

def dedupe(nodes):
    seen = set()
    result = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], n["uuid"], n["security"], n["transport"])
        if key not in seen:
            seen.add(key)
            result.append(n)
    return result

def sort_live(nodes):
    return sorted(nodes, key=lambda n: (n.get("latency_ms", 99999), n["host"]))

def with_label(node, index):
    base = node["uri"].split("#", 1)[0]
    return base + "#" + f"GP-{index:02d}-{node['class']}"

def yaml_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

def clash_proxy(node, index):
    p = node["params"]
    item = {
        "name": f"GP-{index:02d}-{node['class']}",
        "type": "vless",
        "server": node["host"],
        "port": node["port"],
        "uuid": node["uuid"],
        "udp": True,
        "network": p.get("type", "tcp"),
    }
    if p.get("flow"):
        item["flow"] = p["flow"]
    if p.get("security") in ("tls", "reality"):
        item["tls"] = True
        if p.get("sni"):
            item["servername"] = p["sni"]
        if p.get("fp"):
            item["client-fingerprint"] = p["fp"]
    if p.get("security") == "reality":
        reality = {}
        if p.get("pbk"):
            reality["public-key"] = p["pbk"]
        if p.get("sid"):
            reality["short-id"] = p["sid"]
        if reality:
            item["reality-opts"] = reality
    if p.get("type") == "ws":
        ws = {}
        if p.get("path"):
            ws["path"] = p["path"]
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        if ws:
            item["ws-opts"] = ws
    return item

def dump_yaml(nodes):
    lines = ["mixed-port: 7890", "mode: rule", "proxies:"]
    for i, n in enumerate(nodes, 1):
        c = clash_proxy(n, i)
        lines.append(f"  - name: {yaml_quote(c['name'])}")
        lines.append(f"    type: vless")
        lines.append(f"    server: {yaml_quote(c['server'])}")
        lines.append(f"    port: {c['port']}")
        lines.append(f"    uuid: {yaml_quote(c['uuid'])}")
        lines.append(f"    udp: true")
        lines.append(f"    network: {yaml_quote(c['network'])}")
        if c.get("flow"):
            lines.append(f"    flow: {yaml_quote(c['flow'])}")
        if c.get("tls"):
            lines.append("    tls: true")
        if c.get("servername"):
            lines.append(f"    servername: {yaml_quote(c['servername'])}")
        if c.get("client-fingerprint"):
            lines.append(f"    client-fingerprint: {yaml_quote(c['client-fingerprint'])}")
        if c.get("reality-opts"):
            lines.append("    reality-opts:")
            for k, v in c["reality-opts"].items():
                lines.append(f"      {k}: {yaml_quote(v)}")
        if c.get("ws-opts"):
            lines.append("    ws-opts:")
            if c["ws-opts"].get("path"):
                lines.append(f"      path: {yaml_quote(c['ws-opts']['path'])}")
            if c["ws-opts"].get("headers"):
                lines.append("      headers:")
                lines.append(f"        Host: {yaml_quote(c['ws-opts']['headers']['Host'])}")
    lines.append("proxy-groups:")
    lines.append("  - name: AUTO")
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    tolerance: 80")
    lines.append("    proxies:")
    for i in range(1, len(nodes) + 1):
        lines.append(f"      - {yaml_quote(f'GP-{i:02d}-{nodes[i-1]['class']}')}")
    lines.extend(["rules:", "  - MATCH,AUTO", ""])
    return "\n".join(lines)

def main():
    all_nodes = []
    source_stats = {}
    for name, url in SOURCES:
        try:
            payload = fetch(url)
            parsed = [parse_vless(x) for x in decode_payload(payload)]
            parsed = [x for x in parsed if x]
            source_stats[name] = {"fetched": len(parsed), "url": url}
            all_nodes.extend(parsed[:500])
        except Exception as exc:
            source_stats[name] = {"fetched": 0, "error": str(exc), "url": url}

    unique = dedupe(all_nodes)
    live = []
    for node in unique:
        if tcp_check(node):
            live.append(node)

    resilient = sort_live([n for n in live if n["class"] == "RESILIENT"])
    normal = sort_live([n for n in live if n["class"] == "NORMAL"])

    selected = resilient[:TARGET_RESILIENT] + normal[:TARGET_NORMAL]
    selected_keys = {id(x) for x in selected}
    if len(selected) < TARGET:
        for node in sort_live(live):
            if id(node) not in selected_keys:
                selected.append(node)
                selected_keys.add(id(node))
                if len(selected) == TARGET:
                    break

    if len(selected) < TARGET:
        raise RuntimeError(f"Only {len(selected)} live nodes; previous publication is preserved")

    selected = selected[:TARGET]
    for i, node in enumerate(selected, 1):
        node["uri"] = with_label(node, i)

    subscription = "\n".join(n["uri"] for n in selected) + "\n"
    b64 = base64.b64encode(subscription.encode()).decode() + "\n"

    with open(f"{OUT}/GlobalPulse-Subscription.txt", "w", encoding="utf-8") as f:
        f.write(subscription)
    with open(f"{OUT}/GlobalPulse-Base64.txt", "w", encoding="utf-8") as f:
        f.write(b64)
    with open(f"{OUT}/GlobalPulse-NORMAL.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(n["uri"] for n in selected if n["class"] == "NORMAL") + "\n")
    with open(f"{OUT}/GlobalPulse-RESILIENT.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(n["uri"] for n in selected if n["class"] == "RESILIENT") + "\n")
    with open(f"{OUT}/GlobalPulse-AUTO.yaml", "w", encoding="utf-8") as f:
        f.write(dump_yaml(selected))

    stats = {
        "target": TARGET,
        "published": len(selected),
        "resilient": sum(n["class"] == "RESILIENT" for n in selected),
        "normal": sum(n["class"] == "NORMAL" for n in selected),
        "scanned": len(unique),
        "live": len(live),
        "generated_at": int(time.time()),
        "sources": source_stats,
        "nodes": [
            {"name": n["name"], "host": n["host"], "port": n["port"],
             "class": n["class"], "security": n["security"],
             "transport": n["transport"], "latency_ms": n.get("latency_ms")}
            for n in selected
        ],
    }
    with open(f"{OUT}/stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print(json.dumps({
        "published": len(selected),
        "resilient": stats["resilient"],
        "normal": stats["normal"],
        "scanned": len(unique),
        "live": len(live),
    }, ensure_ascii=False))

if __name__ == "__main__":
    main()
