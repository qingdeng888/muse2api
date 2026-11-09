"""Mihomo 桥纯逻辑单测：分享链接解析（7 协议）/ 订阅三段式 / 端口分配 / runtime.yaml 结构。

运行: venv/python tests/test_mihomo.py（无网络）
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_tmp = tempfile.TemporaryDirectory(prefix="muse-mihomo-test-")
os_env = {"MUSE2API_MIHOMO_DIR": str(Path(_tmp.name) / "mihomo")}
import os
os.environ.update(os_env)
import mihomo
from mihomo import (MihomoBridge, AUTO_GROUP, parse_share_links,
                    parse_subscription_payload)


def test_share_link_parsers():
    links = "\n".join([
        # vmess：标准 base64 JSON
        "vmess://" + __import__("base64").b64encode(json.dumps({
            "ps": "测试-VMess", "add": "a.example.com", "port": 443, "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "aid": 0, "net": "ws", "host": "cdn.example.com", "path": "/ws", "tls": "tls"}).encode()).decode(),
        # ss：SIP002 明文 userinfo
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#SS-Node",
        # trojan：ws + sni + insecure
        "trojan://pass-word@t.example.com:443?security=tls&sni=t.example.com&type=ws&path=%2Ftrojan&allowInsecure=1#Trojan-WS",
        # vless：reality
        "vless://uuid-1234@v.example.com:443?security=reality&pbk=PUBKEY123&sid=ab12&fp=chrome&flow=xtls-rprx-vision#VLESS-Reality",
        # hysteria2（hy2 别名 + obfs）
        "hy2://pw123@h.example.com:36712?sni=h.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#HY2-Node",
        # tuic
        "tuic://uuid-abc:tuicpass@t2.example.com:443?sni=t2.example.com&congestion_control=bbr&alpn=h3#TUIC-Node",
        # anytls
        "anytls://anypass@a2.example.com:8443?sni=a2.example.com&insecure=1#AnyTLS-Node",
        "# 注释行", "http://不支持的协议会被跳过", "vmess://!!!坏数据!!!",
    ])
    nodes = parse_share_links(links)
    types = {n["type"] for n in nodes}
    assert types == {"vmess", "ss", "trojan", "vless", "hysteria2", "tuic", "anytls"}, types
    by_type = {n["type"]: n for n in nodes}
    vm = by_type["vmess"]
    assert vm["server"] == "a.example.com" and vm["port"] == 443 and vm["uuid"].startswith("b831381d")
    assert vm["network"] == "ws" and vm["ws-opts"]["headers"]["Host"] == "cdn.example.com" and vm["tls"] is True
    ss = by_type["ss"]
    assert ss["cipher"] == "aes-256-gcm" and ss["password"] == "password"
    tr = by_type["trojan"]
    assert tr["sni"] == "t.example.com" and tr["skip-cert-verify"] is True and tr["ws-opts"]["path"] == "/trojan"
    vl = by_type["vless"]
    assert vl["reality-opts"]["public-key"] == "PUBKEY123" and vl["reality-opts"]["short-id"] == "ab12"
    assert vl["flow"] == "xtls-rprx-vision" and vl["client-fingerprint"] == "chrome"
    hy = by_type["hysteria2"]
    assert hy["obfs"] == "salamander" and hy["obfs-password"] == "obfspw" and hy["skip-cert-verify"] is True
    tu = by_type["tuic"]
    assert tu["congestion-controller"] == "bbr" and tu["alpn"] == ["h3"] and tu["password"] == "tuicpass"
    at = by_type["anytls"]
    assert at["password"] == "anypass" and at["skip-cert-verify"] is True
    print("PASS: share-link parsers (7 protocols incl. reality/tuic/anytls)")


def test_subscription_payload_forms():
    import base64
    clash_yaml = "proxies:\n  - {name: JP-01, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-128-gcm, password: x}\n  - {name: JP-01, type: ss, server: 2.2.2.2, port: 8388, cipher: aes-128-gcm, password: y}"
    nodes = parse_subscription_payload(clash_yaml)
    assert len(nodes) == 1 and nodes[0]["server"] == "1.1.1.1", "Clash YAML 去重保留首个"
    # 整包 base64（内含分享链接）
    b64 = base64.b64encode("vless://u@3.3.3.3:443?security=tls#FromB64".encode()).decode()
    nodes = parse_subscription_payload(b64)
    assert len(nodes) == 1 and nodes[0]["name"] == "FromB64"
    # 原始链接行
    nodes = parse_subscription_payload("trojan://pw@4.4.4.4:443#RawTrojan")
    assert len(nodes) == 1 and nodes[0]["type"] == "trojan"
    print("PASS: subscription payload three-form parsing")


def _fresh_bridge():
    _counter = getattr(_fresh_bridge, "_n", 0) + 1
    _fresh_bridge._n = _counter
    return MihomoBridge()


def test_bridge_state_and_ports():
    b = _fresh_bridge()
    assert b.settings()["enabled"] is False
    err = b.set_settings(enabled=True, base_port=11801)
    assert err is None and b.settings()["base_port"] == 11801
    # 导入两个直出节点
    r = b.import_links("vless://u@5.5.5.5:443?security=tls#N1\nvless://u@6.6.6.6:443?security=tls#N2")
    assert r["added"] == 2
    keys = [x["key"] for x in b.list_nodes()]
    p1 = b.register_direct(keys[0])
    p2 = b.register_direct(keys[1])
    assert p1 == 11801 and p2 == 11802, (p1, p2)
    # 已有分配时禁止修改 base_port
    err = b.set_settings(base_port=12801)
    assert err and "端口分配" in err
    print("PASS: bridge state / port allocation / base_port guard")


def test_build_yaml_structure():
    b = _fresh_bridge()
    b.set_settings(enabled=True)
    b.import_links("vless://u@7.7.7.7:443?security=reality&pbk=PK&sid=S1#Fly1\n"
                   "hy2://pw@8.8.8.8:36712#Fly2")
    nodes = b.list_nodes()
    # 链式：绑定一个池 http 代理走 AUTO 组
    res, err = b.set_chain("poolpid123", AUTO_GROUP, {"id": "poolpid123", "server": "http://user:pw@9.9.9.9:8080"})
    assert not err and res["port"] == b.settings()["base_port"]
    # 另一个链式指定节点
    key1 = nodes[0]["key"]
    res2, err2 = b.set_chain("poolpid456", key1, {"id": "poolpid456", "server": "socks5://10.0.0.1:1080"})
    assert not err2
    entries = [
        {"pid": "poolpid123", "flight": AUTO_GROUP, "config": {"server": "http://user:pw@9.9.9.9:8080"}},
        {"pid": "poolpid456", "flight": key1, "config": {"server": "socks5://10.0.0.1:1080"}},
    ]
    body, secret = b.build_yaml(entries)
    doc = __import__("yaml").safe_load(body)
    assert secret and len(secret) >= 24
    assert doc["mode"] == "global" and doc["dns"] == {"enable": False}
    assert doc["external-controller"] == f"127.0.0.1:{b.settings()['api_port']}"
    # AUTO url-test 组
    groups = doc.get("proxy-groups") or []
    auto = next(g for g in groups if g["name"] == AUTO_GROUP)
    assert auto["type"] == "url-test" and len(auto["proxies"]) == 2
    # 节点内联（限定名）
    names = [p["name"] for p in doc["proxies"]]
    assert key1 in names and "link::Fly2" in names
    # 链式条目带 dialer-proxy
    ch_auto = next(p for p in doc["proxies"] if p["name"].startswith("chain-poolpid"))
    assert ch_auto["dialer-proxy"] == AUTO_GROUP and ch_auto["type"] == "http"
    ch_pin = next(p for p in doc["proxies"] if p["type"] == "socks5" and p["name"].startswith("chain-"))
    assert ch_pin["dialer-proxy"] == key1 and ch_pin["server"] == "10.0.0.1"
    # listeners：每个链式一个 + 无直出（未 register）
    assert len(doc["listeners"]) == 2
    for l in doc["listeners"]:
        assert l["type"] == "socks" and l["listen"] == "127.0.0.1" and l["udp"] is True
    ports = {l["port"] for l in doc["listeners"]}
    assert len(ports) == 2 and b.settings()["api_port"] not in ports
    print("PASS: runtime.yaml structure (chain dialer-proxy / AUTO group / listeners / secret)")


def test_chain_off_and_gc():
    b = _fresh_bridge()
    b.import_links("vless://u@9.9.9.9:443#G1")
    b.set_chain("p1", AUTO_GROUP, {"id": "p1", "server": "http://1.1.1.1:80"})
    assert b.chain_info("p1")["port"]
    b.set_chain("p1", None, None)
    assert b.chain_info("p1") is None
    assert "chain::p1" not in b._port_map
    print("PASS: chain off releases port")


if __name__ == "__main__":
    test_share_link_parsers()
    test_subscription_payload_forms()
    test_bridge_state_and_ports()
    test_build_yaml_structure()
    test_chain_off_and_gc()
    print("ALL MIHOMO TESTS PASSED")
