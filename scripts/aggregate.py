import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

TARGET = 15
TARGET_RESILIENT = 10
TARGET_NORMAL = 5
E2E_MAX_CANDIDATES = int(os.getenv("E2E_MAX_CANDIDATES", "80"))
E2E_TIMEOUT = float(os.getenv("E2E_TIMEOUT", "7"))
E2E_URL = os.getenv("E2E_URL", "https://www.gstatic.com/generate_204")
E2E_PROBES = [
    ("google", "https://www.gstatic.com/generate_204"),
    ("youtube", "https://www.youtube.com/generate_204"),
    ("telegram", "https://api.telegram.org"),
]

SOURCES = [
    ("zieng2-universal", "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"),
    ("mehrtat-vless", "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt"),
    ("baarcuda-top100", "https://raw.githubusercontent.com/Baarcuda/vpn-configs/master/top100-vless.txt"),
    ("vovaplus-secure", "https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure-Base64/vless.txt"),
    ("au1rxx", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/vless.txt"),
    ("morpheusadam", "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/vless.txt"),
]

OUT = "output"
os.makedirs(OUT, exist_ok=True)

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "GlobalPulse/2.0"})
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
    return {
        "uri": uri,
        "host": p.hostname,
        "port": p.port,
        "uuid": p.username,
        "name": unquote(p.fragment) if p.fragment else f"{p.hostname}:{p.port}",
        "security": security,
        "transport": transport,
        "params": {k: v[0] for k, v in q.items()},
        "class": "RESILIENT" if security == "reality" else "NORMAL",
        "transport_priority": 0 if transport == "xhttp" else (1 if transport == "ws" else 2),
    }

def tcp_check(node):
    started = time.monotonic()
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=3.5):
            node["tcp_latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            return True
    except Exception:
        return False

def dedupe(nodes):
    seen, result = set(), []
    for n in nodes:
        key = (n["host"].lower(), n["port"], n["uuid"], n["security"], n["transport"])
        if key not in seen:
            seen.add(key)
            result.append(n)
    return result

def sort_live(nodes):
    return sorted(
        nodes,
        key=lambda n: (
            n.get("tcp_latency_ms", 99999),
            n.get("transport_priority", 9),
            n["host"],
        ),
    )

def xray_config(node, socks_port):
    p = node["params"]
    user = {"id": node["uuid"], "encryption": "none", "level": 0}
    if p.get("flow"):
        user["flow"] = p["flow"]

    stream = {
        "network": p.get("type", "tcp"),
        "security": p.get("security", "none"),
    }

    if stream["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "chrome"),
            "password": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
        }
        if p.get("spx"):
            stream["realitySettings"]["spiderX"] = p["spx"]
    elif stream["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": p.get("sni", ""),
            "allowInsecure": p.get("allowInsecure", "0").lower() in ("1", "true"),
        }
        if p.get("fp"):
            stream["tlsSettings"]["fingerprint"] = p["fp"]
        if p.get("alpn"):
            stream["tlsSettings"]["alpn"] = [x for x in p["alpn"].split(",") if x]

    if stream["network"] == "ws":
        ws = {"path": p.get("path", "/")}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        stream["wsSettings"] = ws
    elif stream["network"] == "xhttp":
        xhttp = {"path": p.get("path", "/"), "mode": p.get("mode", "auto")}
        if p.get("host"):
            xhttp["host"] = p["host"]
        if p.get("extra"):
            try:
                extra = json.loads(p["extra"])
                if isinstance(extra, dict):
                    for key in (
                        "xPaddingBytes", "xPaddingObfsMode", "xPaddingKey",
                        "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod",
                        "uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey",
                        "sessionIDTable", "sessionIDLength", "seqPlacement",
                        "seqKey", "uplinkDataPlacement", "uplinkDataKey",
                        "uplinkChunkSize", "noGRPCHeader", "noSSEHeader",
                        "scMaxEachPostBytes", "scMinPostsIntervalMs",
                        "scMaxBufferedPosts", "scStreamUpServerSecs",
                        "serverMaxHeaderBytes", "xmux", "downloadSettings"
                    ):
                        if key in extra:
                            xhttp[key] = extra[key]
            except json.JSONDecodeError:
                pass
        stream["xhttpSettings"] = xhttp

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": node["host"],
                "port": node["port"],
                "users": [user],
            }]},
            "streamSettings": stream,
        }, {"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }

def e2e_check(node, xray_bin):
    socks_port = 20000 + (abs(hash(node["host"] + str(node["port"]))) % 20000)
    with tempfile.TemporaryDirectory(prefix="globalpulse-") as td:
        cfg = os.path.join(td, "config.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump(xray_config(node, socks_port), f)
        try:
            proc = subprocess.Popen(
                [xray_bin, "run", "-config", cfg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return False, None, "xray-start-failed"

        try:
            ready = False
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.15):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.05)
            if not ready:
                return False, None, "socks-not-ready"

            probe_results = {}
            latencies = []
            for label, url in E2E_PROBES:
                started = time.monotonic()
                cmd = [
                    "curl", "--silent", "--show-error",
                    "--max-time", str(E2E_TIMEOUT),
                    "--socks5-hostname", f"127.0.0.1:{socks_port}",
                    "-o", "/dev/null", "-w", "%{http_code}",
                    url,
                ]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=E2E_TIMEOUT + 2
                    )
                    code = result.stdout.strip()
                    ok = result.returncode == 0 and code in {"200", "204", "301", "302", "401", "403", "404"}
                    probe_results[label] = {"ok": ok, "http_code": code}
                    if ok:
                        latencies.append((time.monotonic() - started) * 1000)
                    else:
                        probe_results[label]["error"] = (result.stderr.strip() or f"curl-exit-{result.returncode}")[:120]
                except subprocess.TimeoutExpired:
                    probe_results[label] = {"ok": False, "error": "timeout"}

            passed = sum(1 for x in probe_results.values() if x["ok"])
            if passed >= 2:
                latency = round(sum(latencies) / len(latencies), 1) if latencies else None
                return True, latency, "ok:" + ",".join(k for k,v in probe_results.items() if v["ok"])

            failed = ",".join(k for k,v in probe_results.items() if not v["ok"])
            return False, None, "probes-failed:" + failed
        except Exception as exc:
            return False, None, ("e2e-error:" + str(exc))[:160]
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()

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
        lines += [
            f"  - name: {yaml_quote(c['name'])}",
            "    type: vless",
            f"    server: {yaml_quote(c['server'])}",
            f"    port: {c['port']}",
            f"    uuid: {yaml_quote(c['uuid'])}",
            "    udp: true",
            f"    network: {yaml_quote(c['network'])}",
        ]
        if c.get("flow"): lines.append(f"    flow: {yaml_quote(c['flow'])}")
        if c.get("tls"): lines.append("    tls: true")
        if c.get("servername"): lines.append(f"    servername: {yaml_quote(c['servername'])}")
        if c.get("client-fingerprint"): lines.append(f"    client-fingerprint: {yaml_quote(c['client-fingerprint'])}")
        if c.get("reality-opts"):
            lines.append("    reality-opts:")
            for k, v in c["reality-opts"].items():
                lines.append(f"      {k}: {yaml_quote(v)}")
        if c.get("ws-opts"):
            lines.append("    ws-opts:")
            if c["ws-opts"].get("path"): lines.append(f"      path: {yaml_quote(c['ws-opts']['path'])}")
            if c["ws-opts"].get("headers"):
                lines += ["      headers:", f"        Host: {yaml_quote(c['ws-opts']['headers']['Host'])}"]
    lines += ["proxy-groups:", "  - name: AUTO", "    type: url-test",
              f"    url: {E2E_URL}", "    interval: 300", "    tolerance: 80", "    proxies:"]
    for i in range(1, len(nodes) + 1):
        lines.append(f"      - {yaml_quote(f'GP-{i:02d}-{nodes[i-1]["class"]}')}")
    lines += ["rules:", "  - MATCH,AUTO", ""]
    return "\n".join(lines)

def main():
    xray_bin = os.getenv("XRAY_BIN", "xray")
    if not os.path.exists(xray_bin) and xray_bin == "xray":
        raise RuntimeError("XRAY_BIN is not available; E2E verification is mandatory")

    all_nodes, source_stats = [], {}
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
    tcp_live = [n for n in unique if tcp_check(n)]
    resilient = sort_live([n for n in tcp_live if n["class"] == "RESILIENT"])
    normal = sort_live([n for n in tcp_live if n["class"] == "NORMAL"])

    # Keep both classes represented in the E2E sample so a lack of one class
    # cannot starve the final 10/5 target split.
    half = max(1, E2E_MAX_CANDIDATES // 2)
    candidates = resilient[:half] + normal[:half]
    candidates = candidates[:E2E_MAX_CANDIDATES]

    verified = []
    failures = []
    for idx, node in enumerate(candidates, 1):
        ok, latency, reason = e2e_check(node, xray_bin)
        if ok:
            node["latency_ms"] = latency
            node["e2e"] = True
            verified.append(node)
        else:
            node["e2e"] = False
            node["e2e_error"] = reason
            failures.append(node)
        print(f"E2E {idx}/{len(candidates)} {'OK' if ok else 'FAIL'} {node['host']}:{node['port']} {reason}", flush=True)
        if sum(n["class"] == "RESILIENT" for n in verified) >= TARGET_RESILIENT and sum(n["class"] == "NORMAL" for n in verified) >= TARGET_NORMAL:
            break

    verified_resilient = sort_live([n for n in verified if n["class"] == "RESILIENT"])
    verified_normal = sort_live([n for n in verified if n["class"] == "NORMAL"])
    verified_xhttp = sort_live([n for n in verified if n["transport"] == "xhttp"])

    # INCY compatibility: keep a guaranteed XHTTP slice when E2E-verified.
    # The previous class-only 10/5 selection could discard all XHTTP nodes
    # even when they had passed the same end-to-end probes.
    XHTTP_RESERVE = min(5, len(verified_xhttp), TARGET)
    selected = verified_xhttp[:XHTTP_RESERVE]
    selected_keys = {id(x) for x in selected}

    for node in verified_resilient:
        if sum(x["class"] == "RESILIENT" for x in selected) >= TARGET_RESILIENT:
            break
        if id(node) not in selected_keys:
            selected.append(node)
            selected_keys.add(id(node))

    for node in verified_normal:
        if sum(x["class"] == "NORMAL" for x in selected) >= TARGET_NORMAL:
            break
        if id(node) not in selected_keys:
            selected.append(node)
            selected_keys.add(id(node))

    # Fill remaining slots by overall verified quality, preserving the XHTTP reserve.
    if len(selected) < TARGET:
        for node in sort_live(verified):
            if id(node) not in selected_keys:
                selected.append(node)
                selected_keys.add(id(node))
                if len(selected) == TARGET:
                    break

    if len(selected) < TARGET:
        raise RuntimeError(
            f"E2E verification produced only {len(selected)} working nodes "
            f"(need {TARGET}); previous publication is preserved"
        )

    selected = selected[:TARGET]
    for i, node in enumerate(selected, 1):
        node["uri"] = with_label(node, i)

    # INCY routing profile: force all traffic through the selected proxy and
    # resolve proxy-side DNS via DoH, instead of relying on Android defaults.
    incy_profile = {
        "Name": "GlobalPulse Full Proxy",
        "GlobalProxy": "true",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomainStrategy": "IPIfNonMatch",
    }
    incy_routing = "incy://routing/onadd/" + base64.b64encode(
        json.dumps(incy_profile, ensure_ascii=False, separators=(",", ":")).encode()
    ).decode() + "\n"

    # INCY-compatible static subscription metadata. INCY supports these body
    # directives as a fallback when the hosting server cannot set HTTP headers.
    incy_header = (
        "#profile-title: GlobalPulse INCY\n"
        "#profile-description: E2E-verified VLESS servers\n"
        "#profile-update-interval: 1\n"
        "#sort-order: ping\n"
    )
    subscription = incy_header + incy_routing + "\n".join(n["uri"] for n in selected) + "\n"
    b64 = base64.b64encode(subscription.encode()).decode() + "\n"

    for filename, data in {
        "GlobalPulse-Subscription.txt": subscription,
        "GlobalPulse-Base64.txt": b64,
        "GlobalPulse-NORMAL.txt": "\n".join(n["uri"] for n in selected if n["class"] == "NORMAL") + "\n",
        "GlobalPulse-RESILIENT.txt": "\n".join(n["uri"] for n in selected if n["class"] == "RESILIENT") + "\n",
        "GlobalPulse-AUTO.yaml": dump_yaml(selected),
    }.items():
        with open(f"{OUT}/{filename}", "w", encoding="utf-8") as f:
            f.write(data)

    stats = {
        "target": TARGET, "published": len(selected),
        "resilient": sum(n["class"] == "RESILIENT" for n in selected),
        "normal": sum(n["class"] == "NORMAL" for n in selected),
        "scanned": len(unique), "tcp_live": len(tcp_live),
        "e2e_candidates": len(candidates), "e2e_verified": len(verified),
        "e2e_failed": len(failures), "generated_at": int(time.time()),
        "verification": "xray-vless-e2e-multi-probe-via-socks",
        "test_url": E2E_URL, "probes": {k: u for k, u in E2E_PROBES}, "sources": source_stats,
        "xhttp_verified": sum(n["transport"] == "xhttp" for n in verified),
        "xhttp_published": sum(n["transport"] == "xhttp" for n in selected),
        "nodes": [{
            "name": n["name"], "host": n["host"], "port": n["port"],
            "class": n["class"], "security": n["security"],
            "transport": n["transport"], "latency_ms": n.get("latency_ms"),
            "tcp_latency_ms": n.get("tcp_latency_ms"), "e2e": True
        } for n in selected],
    }
    with open(f"{OUT}/stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print(json.dumps({
        "published": len(selected), "resilient": stats["resilient"],
        "normal": stats["normal"], "scanned": len(unique),
        "tcp_live": len(tcp_live), "e2e_verified": len(verified)
    }, ensure_ascii=False))

if __name__ == "__main__":
    main()
