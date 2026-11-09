"""Mihomo 代理桥：飞行节点（vless/vmess/trojan/ss/hysteria2/tuic/anytls）托管层。

设计参考 ds2api 的 internal/mihomo（CJackHwang/ds2api fork）：
- 每个出口目标一个本地 SOCKS listener（mihomo listeners[].proxy 钉死），"一端口=一出口"；
- 订阅/分享链接在添加时就地解析为 Clash 节点并内联进 runtime.yaml（无 provider），
  节点名限定 `source::name` 防跨订阅重名；
- 链式封装：被桥接的池内 http/socks 代理转成 mihomo 条目并加 `dialer-proxy`
  指向 BRIDGE-AUTO（url-test 自动选优组）或指定飞行节点，实现"先飞加密层再出原生代理"；
- 二进制按需下载（ghfast.top 镜像优先 → GitHub），支持手动放置；/version+Bearer
  就绪探测；配置未变跳过重启；看门狗自愈；应用退出回收子进程。

持久层 data/mihomo.json 只存配置与节点；健康/进程状态全在内存。
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import threading
import time
import zipfile
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, unquote, urlsplit

import requests
import yaml

from config import CFG

# ------------------------- 分享链接解析 -------------------------

def _b64_loose(data: str) -> bytes | None:
    """宽松 base64：容忍缺 padding 与 URL 变体；明显不像 base64 时返回 None。"""
    s = "".join(data.split())
    if not s or len(s.rstrip("=")) % 4 == 1:
        return None
    if not all(c.isalnum() or c in "+-/_" or c == "=" for c in s):
        return None
    for cand in (s, s + "=" * (-len(s) % 4)):
        for alt in (cand, cand.replace("+", "-").replace("/", "_")):
            try:
                return base64.b64decode(alt, validate=True)
            except (binascii.Error, ValueError):
                continue
    return None


def _scheme(line: str) -> str:
    idx = line.find("://")
    return line[:idx].lower() if 0 < idx <= 12 else ""


def _qfirst(q: dict, *keys) -> str:
    for k in keys:
        v = str(q.get(k, "") or "").strip()
        if v:
            return v
    return ""


def _qbool(q: dict, *keys) -> bool:
    return _qfirst(q, *keys).lower() in ("1", "true", "yes")


def _alpn_list(raw: str) -> list | None:
    parts = [p.strip() for p in (raw or "").split(",") if p.strip()]
    return parts or None


def _name_of(host: str, frag: str, fallback: str = "") -> str:
    return unquote(frag).strip() or fallback.strip() or host


def _ws_opts(q: dict) -> dict | None:
    opts = {}
    path = str(q.get("path", "") or "").strip()
    host = _qfirst(q, "host")
    if path:
        opts["path"] = path
    if host:
        opts["headers"] = {"Host": host}
    return opts or None


def _node(raw: dict) -> dict | None:
    name = str(raw.get("name") or "").strip()
    ntype = str(raw.get("type") or "").strip().lower()
    server = str(raw.get("server") or "").strip()
    port = raw.get("port") or 0
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not name or not ntype or not server or port <= 0:
        return None
    # REALITY 公钥必须是 32 字节的 base64url（无 padding），否则 mihomo 启动即 fatal。
    # 导入时就拦下来，比让整个桥起不来友好得多。
    if ntype == "vless" and isinstance(raw.get("reality-opts"), dict):
        pbk = str(raw["reality-opts"].get("public-key") or "").strip()
        try:
            decoded = base64.urlsafe_b64decode(pbk + "=" * (-len(pbk) % 4))
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) != 32:
            return None
    raw["name"] = name
    raw["type"] = ntype
    raw["port"] = port
    return raw


def _parse_vmess(line: str) -> dict | None:
    payload = line[len("vmess://"):]
    decoded = _b64_loose(payload)
    if not decoded:
        return None
    try:
        doc = json.loads(decoded)
    except ValueError:
        return None
    raw = {"name": str(doc.get("ps") or "").strip(), "type": "vmess",
           "server": str(doc.get("add") or "").strip(),
           "port": doc.get("port"), "uuid": str(doc.get("id") or "").strip(),
           "alterId": doc.get("aid") or 0, "cipher": str(doc.get("scy") or "auto")}
    net = str(doc.get("net") or "tcp").lower()
    if net and net != "tcp":
        raw["network"] = net
    if net == "ws":
        ws = {}
        if str(doc.get("path") or "").strip():
            ws["path"] = str(doc["path"]).strip()
        if str(doc.get("host") or "").strip():
            ws["headers"] = {"Host": str(doc["host"]).strip()}
        if ws:
            raw["ws-opts"] = ws
    if str(doc.get("tls") or "").lower() == "tls":
        raw["tls"] = True
        sni = str(doc.get("sni") or doc.get("host") or "").strip()
        if sni:
            raw["servername"] = sni
        alpn = _alpn_list(str(doc.get("alpn") or ""))
        if alpn:
            raw["alpn"] = alpn
    return _node(raw)


def _parse_ss(line: str) -> dict | None:
    payload = line[len("ss://"):]
    name = ""
    if "#" in payload:
        payload, frag = payload.split("#", 1)
        name = unquote(frag).strip()
        payload = payload.strip()
    if "/?" in payload:
        payload = payload.split("/?", 1)[0]
    method = password = host = ""
    port = 0
    if "@" in payload:
        userinfo, server_part = payload.rsplit("@", 1)
        decoded = _b64_loose(userinfo)
        userinfo = decoded.decode() if decoded else unquote(userinfo)
        method, _, password = userinfo.partition(":")
        u = urlsplit("ss://" + server_part)
        host = (u.hostname or "").strip("[]")
        try:
            port = u.port
        except ValueError:
            return None
    else:
        decoded = _b64_loose(payload)
        if not decoded:
            return None
        full = decoded.decode(errors="replace")
        if "@" not in full:
            return None
        userinfo, server_part = full.rsplit("@", 1)
        method, _, password = userinfo.partition(":")
        u = urlsplit("ss://" + server_part)
        host = (u.hostname or "").strip("[]")
        try:
            port = u.port
        except ValueError:
            return None
    return _node({"name": name or host, "type": "ss", "server": host, "port": port,
                  "cipher": method, "password": password})


def _parse_trojan(line: str) -> dict | None:
    u = urlsplit(line)
    try:
        port = u.port
    except ValueError:
        return None
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    raw = {"name": _name_of(u.hostname or "", u.fragment), "type": "trojan",
           "server": (u.hostname or "").strip("[]"), "port": port,
           "password": unquote(u.username or "")}
    sni = _qfirst(q, "sni", "peer")
    if sni:
        raw["sni"] = sni
    if _qbool(q, "allowInsecure", "allow_insecure", "insecure"):
        raw["skip-cert-verify"] = True
    alpn = _alpn_list(q.get("alpn", ""))
    if alpn:
        raw["alpn"] = alpn
    if str(q.get("type", "")).lower() == "ws":
        raw["network"] = "ws"
        ws = _ws_opts(q)
        if ws:
            raw["ws-opts"] = ws
    return _node(raw)


def _parse_vless(line: str) -> dict | None:
    u = urlsplit(line)
    try:
        port = u.port
    except ValueError:
        return None
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    raw = {"name": _name_of(u.hostname or "", u.fragment), "type": "vless",
           "server": (u.hostname or "").strip("[]"), "port": port,
           "uuid": unquote(u.username or "")}
    security = _qfirst(q, "security").lower()
    if security == "tls":
        raw["tls"] = True
    elif security == "reality":
        raw["tls"] = True
        ropts = {}
        if q.get("pbk"):
            ropts["public-key"] = str(q["pbk"]).strip()
        if q.get("sid"):
            ropts["short-id"] = str(q["sid"]).strip()
        if ropts:
            raw["reality-opts"] = ropts
    sni = _qfirst(q, "sni")
    if sni:
        raw["servername"] = sni
    if q.get("flow"):
        raw["flow"] = str(q["flow"]).strip()
    if q.get("fp"):
        raw["client-fingerprint"] = str(q["fp"]).strip()
    net = _qfirst(q, "type").lower()
    if net and net != "tcp":
        raw["network"] = net
    if net == "ws":
        ws = _ws_opts(q)
        if ws:
            raw["ws-opts"] = ws
    if _qbool(q, "allowInsecure", "allow_insecure", "insecure"):
        raw["skip-cert-verify"] = True
    return _node(raw)


def _parse_hysteria2(line: str) -> dict | None:
    u = urlsplit("hysteria2://" + line.split("://", 1)[1])
    try:
        port = u.port
    except ValueError:
        return None
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    raw = {"name": _name_of(u.hostname or "", u.fragment), "type": "hysteria2",
           "server": (u.hostname or "").strip("[]"), "port": port,
           "password": unquote(u.username or "")}
    sni = _qfirst(q, "sni")
    if sni:
        raw["sni"] = sni
    if _qbool(q, "insecure", "allowInsecure", "allow_insecure"):
        raw["skip-cert-verify"] = True
    obfs = _qfirst(q, "obfs")
    if obfs:
        raw["obfs"] = obfs
        if q.get("obfs-password"):
            raw["obfs-password"] = str(q["obfs-password"]).strip()
    return _node(raw)


def _parse_tuic(line: str) -> dict | None:
    u = urlsplit(line)
    try:
        port = u.port
    except ValueError:
        return None
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    raw = {"name": _name_of(u.hostname or "", u.fragment), "type": "tuic",
           "server": (u.hostname or "").strip("[]"), "port": port,
           "uuid": unquote(u.username or ""), "password": unquote(u.password or "")}
    sni = _qfirst(q, "sni")
    if sni:
        raw["sni"] = sni
    cc = _qfirst(q, "congestion_control")
    if cc:
        raw["congestion-controller"] = cc
    alpn = _alpn_list(q.get("alpn", ""))
    if alpn:
        raw["alpn"] = alpn
    if _qbool(q, "allow_insecure", "insecure", "allowInsecure"):
        raw["skip-cert-verify"] = True
    return _node(raw)


def _parse_anytls(line: str) -> dict | None:
    u = urlsplit(line)
    try:
        port = u.port
    except ValueError:
        return None
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    raw = {"name": _name_of(u.hostname or "", u.fragment), "type": "anytls",
           "server": (u.hostname or "").strip("[]"), "port": port,
           "password": unquote(u.username or "")}
    sni = _qfirst(q, "sni")
    if sni:
        raw["sni"] = sni
    if _qbool(q, "insecure", "allowInsecure", "allow_insecure"):
        raw["skip-cert-verify"] = True
    return _node(raw)


_PARSERS = {"vmess": _parse_vmess, "ss": _parse_ss, "trojan": _parse_trojan,
            "vless": _parse_vless, "hysteria2": _parse_hysteria2, "hy2": _parse_hysteria2,
            "tuic": _parse_tuic, "anytls": _parse_anytls}


def parse_share_links(body: str) -> list[dict]:
    """按行解析分享链接为 Clash 节点字典；坏行跳过，同名去重，稳定排序。"""
    nodes: list[dict] = []
    seen: set[str] = set()
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        parser = _PARSERS.get(_scheme(line))
        if not parser:
            continue
        try:
            node = parser(line)
        except Exception:  # noqa: BLE001 — 单行坏数据不影响整批
            node = None
        if not node or node["name"] in seen:
            continue
        seen.add(node["name"])
        nodes.append(node)
    nodes.sort(key=lambda n: n["name"])
    return nodes


def parse_subscription_payload(text: str) -> list[dict]:
    """订阅正文三段式解析：Clash YAML → 整包 base64（→YAML/链接）→ 原始链接行。"""
    text = (text or "").strip()
    if not text:
        return []
    if "proxies:" in text:
        try:
            doc = yaml.safe_load(text)
            items = doc.get("proxies") if isinstance(doc, dict) else None
            if isinstance(items, list):
                out, seen = [], set()
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    node = _node(dict(item))
                    if node and node["name"] not in seen:
                        seen.add(node["name"])
                        out.append(node)
                out.sort(key=lambda n: n["name"])
                if out:
                    return out
        except yaml.YAMLError:
            pass
    decoded = _b64_loose(text)
    if decoded:
        body = decoded.decode(errors="replace")
        try:
            doc = yaml.safe_load(body)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                out = [_node(dict(i)) for i in doc["proxies"] if isinstance(i, dict)]
                out = [n for n in out if n]
                if out:
                    out.sort(key=lambda n: n["name"])
                    return out
        except yaml.YAMLError:
            pass
        links = parse_share_links(body)
        if links:
            return links
    return parse_share_links(text)



# ------------------------- 桥本体 -------------------------

MIHOMO_VERSION = os.environ.get("MUSE2API_MIHOMO_VERSION", "v1.19.29")
MIHOMO_DOWNLOAD_MIRRORS = ["https://ghfast.top/", ""]
_DOWNLOAD_MAX_BYTES = 256 << 20
AUTO_GROUP = "BRIDGE-AUTO"


@contextmanager
def _thread_pool(workers: int):
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        yield pool
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


class MihomoBridge:
    """mihomo 子进程与飞行节点的全托管状态机。线程安全。"""

    def __init__(self):
        self.dir = os.environ.get("MUSE2API_MIHOMO_DIR") or os.path.join(CFG.data_dir, "mihomo")
        self.state_path = os.path.join(self.dir, "mihomo.json")
        self.config_path = os.path.join(self.dir, "runtime.yaml")
        self.log_path = os.path.join(self.dir, "mihomo.log")
        self._lock = threading.RLock()
        self._apply_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._api_secret = ""
        self._last_yaml = b""
        self._last_error = ""
        self._running_pid = 0
        self.download = {"state": "idle", "percent": 0, "error": ""}
        self._enabled = False
        self._base_port = 10801
        self._api_port = 19090
        self._subscriptions: list[dict] = []
        self._nodes: list[dict] = []
        self._port_map: dict[str, int] = {}
        self._chains: dict[str, dict] = {}
        self._disabled: set[str] = set()      # 用户停用的节点 key
        self._removed: set[str] = set()       # 用户删除的节点 key（刷新不复活）
        self._delays: dict[str, dict] = {}    # 节点延迟测试结果（内存）
        self._wake = threading.Event()
        self._load()

    # ---------- 持久化 ----------
    def _load(self):
        try:
            with open(self.state_path, encoding="utf-8") as f:
                data = json.load(f)
            self._enabled = bool(data.get("enabled", False))
            self._base_port = int(data.get("base_port") or 10801)
            self._api_port = int(data.get("api_port") or 19090)
            self._subscriptions = data.get("subscriptions") or []
            self._nodes = data.get("nodes") or []
            self._port_map = data.get("port_map") or {}
            self._chains = data.get("chains") or {}
            self._disabled = set(data.get("disabled_nodes") or [])
            self._removed = set(data.get("removed_nodes") or [])
            for n in self._nodes:
                n.setdefault("enabled", n["key"] not in self._disabled)
        except (OSError, ValueError):
            pass

    def _save(self):
        os.makedirs(self.dir, exist_ok=True)
        data = {"enabled": self._enabled, "base_port": self._base_port,
                "api_port": self._api_port, "subscriptions": self._subscriptions,
                "nodes": self._nodes, "port_map": self._port_map, "chains": self._chains,
                "disabled_nodes": sorted(self._disabled),
                "removed_nodes": sorted(self._removed)}
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.state_path)

    # ---------- 设置 / 视图 ----------
    def settings(self) -> dict:
        with self._lock:
            return {"enabled": self._enabled, "base_port": self._base_port,
                    "api_port": self._api_port}

    def set_settings(self, enabled: bool | None = None, base_port: int | None = None,
                     api_port: int | None = None) -> dict | None:
        with self._lock:
            if base_port is not None:
                if self._port_map and base_port != self._base_port:
                    return f"已存在 {len(self._port_map)} 个端口分配，请先移除全部桥接与直出后再修改 base_port"
                self._base_port = max(1024, int(base_port))
            if api_port is not None:
                if api_port in self._port_map.values():
                    return "api_port 与监听端口冲突"
                self._api_port = max(1024, int(api_port))
            if enabled is not None:
                self._enabled = bool(enabled)
            self._save()
            self._wake.set()
        return None

    def status(self) -> dict:
        with self._lock:
            binary = self.resolve_binary()
            st = {
                "enabled": self._enabled, "running": self.is_running(),
                "pid": self._running_pid, "last_error": self._last_error,
                "binary_found": bool(binary),
                "binary_path": (binary or ""),
                "download": dict(self.download),
                "base_port": self._base_port, "api_port": self._api_port,
                "nodes": len(self._nodes), "subscriptions": len(self._subscriptions),
                "subscription_list": [dict(s) for s in self._subscriptions],
                "chains": {k: dict(v) for k, v in self._chains.items()},
                "port_map": dict(self._port_map),
                "work_dir": self.dir,
            }
        return st

    # ---------- 订阅 ----------
    def add_subscription(self, name: str, url: str) -> tuple[dict | None, str]:
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")):
            return None, "订阅链接必须是 http(s) 地址"
        try:
            nodes = self._fetch_subscription(url)
        except Exception as exc:  # noqa: BLE001
            return None, f"订阅拉取失败：{exc}"
        if not nodes:
            return None, "订阅内容未解析出任何节点（支持 Clash YAML / base64 / 分享链接）"
        with self._lock:
            sid = secrets.token_hex(4)
            sub = {"id": sid, "name": (name or f"订阅-{sid}").strip(), "url": url,
                   "updated_at": int(time.time()), "node_count": len(nodes)}
            self._subscriptions.append(sub)
            self._upsert_nodes(sid, nodes)
            self._save()
            return sub, ""

    def _fetch_subscription(self, url: str) -> list[dict]:
        r = requests.get(url, timeout=30, headers={"User-Agent": "clash.meta/v1.18.0"},
                         stream=True)
        r.raise_for_status()
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > (16 << 20):
                raise ValueError("订阅内容超过 16MB 上限")
        return parse_subscription_payload(body.decode(errors="replace"))

    def refresh_subscription(self, sid: str) -> tuple[dict | None, str]:
        with self._lock:
            sub = next((s for s in self._subscriptions if s["id"] == sid), None)
        if not sub:
            return None, "订阅不存在"
        try:
            nodes = self._fetch_subscription(sub["url"])
        except Exception as exc:  # noqa: BLE001
            return None, f"订阅拉取失败：{exc}"
        with self._lock:
            sub["updated_at"] = int(time.time())
            sub["node_count"] = len(nodes)
            self._upsert_nodes(sid, nodes)
            self._save()
        return sub, ""

    def delete_subscription(self, sid: str) -> bool:
        with self._lock:
            before = len(self._subscriptions)
            self._subscriptions = [s for s in self._subscriptions if s["id"] != sid]
            changed = len(self._subscriptions) != before
            if changed:
                self._nodes = [n for n in self._nodes if n.get("source") != sid]
                self._gc()
                self._save()
            return changed

    def import_links(self, text: str) -> dict:
        nodes = parse_share_links(text)
        if not nodes:
            return {"added": 0, "error": "未解析出任何节点（支持 vless/vmess/trojan/ss/hysteria2(hy2)/tuic/anytls 链接）"}
        with self._lock:
            before = {n["key"] for n in self._nodes}
            self._upsert_nodes("link", nodes)
            added = len([n for n in self._nodes if n["source"] == "link"]) - len(
                [k for k in before if k.startswith("link::")])
            self._save()
        return {"added": max(0, added)}

    def _upsert_nodes(self, source: str, nodes: list[dict]):
        """source::name 限定命名；同源替换、跨源共存。
        已停用的节点与手动删除的墓碑（_disabled/_removed）在刷新后保持原状态，
        否则每次刷新订阅都"复活"用户刻意关掉/删掉的节点。"""
        fresh = []
        for n in nodes:
            key = f"{source}::{n['name']}"
            if key in self._removed:
                continue                       # 用户手动删除过 → 刷新不复活
            raw = {k: v for k, v in n.items()}
            raw["name"] = key          # 内联进 mihomo 的名字用限定名
            fresh.append({"key": key, "source": source, "name": n["name"],
                          "type": n["type"], "server": n["server"], "port": n["port"],
                          "enabled": key not in self._disabled,
                          "raw": raw})
        self._nodes = [n for n in self._nodes if n.get("source") != source] + fresh
        self._nodes.sort(key=lambda n: n["key"])
        self._gc_ports()      # 节点被订阅刷新移除 → 释放其直出端口

    def list_nodes(self) -> list[dict]:
        with self._lock:
            return [{"key": n["key"], "name": n["name"], "type": n["type"],
                     "server": n["server"], "port": n["port"],
                     "enabled": n.get("enabled", True),
                     "source": ("订阅" if n["source"] != "link" else
                                next((s["name"] for s in self._subscriptions
                                      if s["id"] == n["source"]), "链接导入")),
                     "source_id": n["source"],
                     "direct_port": self._port_map.get(n["key"]),
                     "delay_ms": (self._delays.get(n["key"]) or {}).get("delay_ms"),
                     "delay_at": (self._delays.get(n["key"]) or {}).get("at"),
                     "delay_error": (self._delays.get(n["key"]) or {}).get("error", "")}
                    for n in self._nodes]

    def enabled_node_keys(self) -> list[str]:
        with self._lock:
            return [n["key"] for n in self._nodes if n.get("enabled", True)]

    # ---------- 节点批量操作 ----------
    def set_nodes_enabled(self, keys: list[str], enabled: bool) -> dict:
        changed, skipped = [], []
        with self._lock:
            known = {n["key"] for n in self._nodes}
            for key in keys:
                if key not in known:
                    skipped.append(key)
                    continue
                if enabled:
                    self._disabled.discard(key)
                else:
                    self._disabled.add(key)
                for n in self._nodes:
                    if n["key"] == key:
                        n["enabled"] = enabled
                if not enabled:
                    self._port_map.pop(key, None)   # 停用 → 释放直出端口
                changed.append(key)
            self._save()
        return {"changed": changed, "skipped": skipped}

    def remove_nodes(self, keys: list[str]) -> dict:
        """删除节点（订阅节点加墓碑，刷新后不复活）。"""
        removed, skipped = [], []
        with self._lock:
            known = {n["key"] for n in self._nodes}
            for key in keys:
                if key not in known:
                    skipped.append(key)
                    continue
                self._removed.add(key)
                self._port_map.pop(key, None)
                self._delays.pop(key, None)
                for pid, ch in list(self._chains.items()):
                    if ch.get("flight") == key:
                        self._chains.pop(pid, None)
                        self._port_map.pop("chain::" + pid, None)
                self._nodes = [n for n in self._nodes if n["key"] != key]
                removed.append(key)
            self._save()
        return {"removed": removed, "skipped": skipped}

    def test_nodes(self, keys: list[str]) -> dict:
        """通过 mihomo 控制 API 批量测延迟（/proxies/{name}/delay）。
        返回每条结果；桥未运行时整体报错，避免"全都失败"被误读成节点坏了。"""
        if not self.is_running():
            return {"ok": False, "error": "桥未运行：请先在状态卡启用桥接再测试节点", "results": []}
        targets = [k for k in keys if any(n["key"] == k for n in self._nodes)]
        results = []

        def probe(key: str) -> dict:
            try:
                r = requests.get(
                    f"http://127.0.0.1:{self._api_port}/proxies/{requests.utils.quote(key, safe='')}/delay",
                    params={"url": "https://www.gstatic.com/generate_204", "timeout": 5000},
                    headers={"Authorization": "Bearer " + self._api_secret},
                    timeout=8)
                data = r.json() if r.content else {}
                if r.status_code >= 400 or not (data.get("delay") or 0) > 0:
                    raise ValueError(data.get("message") or f"HTTP {r.status_code}")
                return {"key": key, "ok": True, "delay_ms": int(data["delay"]), "error": ""}
            except Exception as exc:  # noqa: BLE001
                return {"key": key, "ok": False, "delay_ms": None, "error": str(exc)[:160]}

        with _thread_pool(8) as pool:
            results = list(pool.map(probe, targets))
        with self._lock:
            now = int(time.time())
            for res in results:
                self._delays[res["key"]] = {"delay_ms": res.get("delay_ms"),
                                            "error": res.get("error", ""), "at": now}
        return {"ok": True, "results": results}

    def list_subscriptions(self) -> list[dict]:
        with self._lock:
            return [dict(s) for s in self._subscriptions]

    # ---------- 端口分配 / 链式 / 直出 ----------
    def _alloc_port(self, key: str) -> int:
        with self._lock:
            if key in self._port_map:
                return self._port_map[key]
            used = set(self._port_map.values()) | {self._api_port}
            port = self._base_port
            while port in used:
                port += 1
            self._port_map[key] = port
            return port

    def _gc(self):
        """节点消失 → 释放其直出端口；链式端口只在关闭链式时释放。"""
        live_nodes = {n["key"] for n in self._nodes}
        keep = set()
        for k in self._port_map:
            if k.startswith("chain::"):
                keep.add(k)          # 链式端口由 set_chain(None) 显式释放
            elif k in live_nodes:
                keep.add(k)
        self._port_map = {k: v for k, v in self._port_map.items() if k in keep}
        chains_ports = {"chain::" + pid for pid in self._chains}
        self._port_map = {k: v for k, v in self._port_map.items()
                          if not k.startswith("chain::") or k in chains_ports}

    def set_chain(self, pool_pid: str, flight: str | None,
                  pool_entry: dict | None) -> tuple[dict | None, str]:
        """为池内 http/socks 代理开/关桥接。flight=None 关闭；
        'AUTO'（也接受 BRIDGE-AUTO）=自动选优组；其余=指定飞行节点。"""
        with self._lock:
            if flight is None:
                self._chains.pop(pool_pid, None)
                self._port_map.pop("chain::" + pool_pid, None)
                self._save()
                return {"ok": True}, ""
            if flight == AUTO_GROUP:
                flight = "AUTO"
            if flight != "AUTO" and not any(n["key"] == flight for n in self._nodes):
                return None, "指定的飞行节点不存在"
            if not pool_entry or not pool_entry.get("server"):
                return None, "池代理不存在"
            scheme = pool_entry["server"].split("://", 1)[0].lower()
            if scheme not in ("http", "socks5", "socks5h"):
                return None, "仅 http / socks5 代理支持链式封装"
            self._chains[pool_pid] = {"flight": flight}
            port = self._alloc_port("chain::" + pool_pid)
            self._save()
            return {"ok": True, "port": port}, ""

    def chain_info(self, pool_pid: str) -> dict | None:
        with self._lock:
            ch = self._chains.get(pool_pid)
            if not ch:
                return None
            return {"flight": ch.get("flight"), "port": self._port_map.get("chain::" + pool_pid)}

    def register_direct(self, node_key: str) -> int | None:
        """直出：为飞行节点分配本地监听端口（导入池时调用）。"""
        with self._lock:
            node = next((n for n in self._nodes if n["key"] == node_key), None)
            if not node:
                return None
            if not node.get("enabled", True):
                return None       # 停用节点不开监听
            return self._alloc_port(node_key)

    def _gc_ports(self):
        self._gc()

    # ---------- runtime.yaml ----------
    def build_yaml(self, chain_entries: list[dict]) -> tuple[bytes, str]:
        """生成 runtime.yaml。chain_entries: [{pid, flight, config(池代理 dict)}]。
        返回 (yaml 字节, 本次 API secret)。"""
        with self._lock:
            active = [n for n in self._nodes if n.get("enabled", True)]
            flight_names = [n["key"] for n in active]
            proxies: list[dict] = [dict(n["raw"]) for n in active]
            listeners: list[dict] = []
            used_ports: set[int] = set()

            def alloc_port(key: str) -> int:
                if key in self._port_map:
                    return self._port_map[key]
                port = self._base_port
                while port in used_ports or port == self._api_port or port in self._port_map.values():
                    port += 1
                self._port_map[key] = port
                return port

            # 链式条目：池代理 → dialer-proxy 飞行层
            for c in chain_entries:
                cfg = c["config"]
                u = urlsplit(cfg["server"])
                try:
                    port = u.port or (1080 if u.scheme.startswith("socks") else 80)
                except ValueError:
                    continue
                name = f"chain-{c['pid'][:8]}"
                entry = {"name": name, "type": "socks5" if u.scheme.startswith("socks") else "http",
                         "server": (u.hostname or "").strip("[]"), "port": port}
                if u.username:
                    entry["username"] = unquote(u.username)
                if u.password:
                    entry["password"] = unquote(u.password)
                dial = AUTO_GROUP if (not c["flight"] or c["flight"] in ("AUTO", AUTO_GROUP)) else c["flight"]
                if flight_names:
                    entry["dialer-proxy"] = dial
                proxies.append(entry)
                lport = alloc_port("chain::" + c["pid"])
                used_ports.add(lport)
                listeners.append({"name": f"muse-in-{lport}", "type": "socks",
                                  "listen": "127.0.0.1", "port": lport, "udp": True,
                                  "proxy": name})
            # 直出节点：池条目已指向 127.0.0.1:port 的节点监听
            for n in active:
                if n["key"] in self._port_map:
                    lport = self._port_map[n["key"]]
                    if lport in used_ports:
                        continue
                    used_ports.add(lport)
                    listeners.append({"name": f"muse-in-{lport}", "type": "socks",
                                      "listen": "127.0.0.1", "port": lport, "udp": True,
                                      "proxy": n["key"]})
            doc = {"log-level": "warning", "allow-lan": False, "mode": "global",
                   "ipv6": False, "dns": {"enable": False}, "rules": ["MATCH,DIRECT"],
                   "external-controller": f"127.0.0.1:{self._api_port}"}
            secret = secrets.token_hex(18)
            doc["secret"] = secret
            if flight_names:
                doc["proxy-groups"] = [{"name": AUTO_GROUP, "type": "url-test",
                                        "proxies": flight_names,
                                        "url": "https://www.gstatic.com/generate_204",
                                        "interval": 300, "tolerance": 50}]
            doc["proxies"] = proxies
            doc["listeners"] = listeners
            body = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False).encode()
            self._save()
            return body, secret

    # ---------- 二进制 ----------
    def resolve_binary(self) -> str | None:
        candidates = [
            os.environ.get("MUSE2API_MIHOMO_PATH") or "",
            os.path.join(CFG.base_dir, "bin", "mihomo.exe" if os.name == "nt" else "mihomo"),
            os.path.join(self.dir, "mihomo.exe" if os.name == "nt" else "mihomo"),
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return shutil.which("mihomo")

    def _asset_name(self) -> str:
        system = platform.system().lower()          # windows / linux / darwin
        machine = platform.machine().lower()
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
        ext = ".zip" if system == "windows" else ".gz"
        return f"mihomo-{system}-{arch}-{MIHOMO_VERSION}{ext}"

    def download_binary(self):
        """后台线程：镜像优先 → GitHub 直连。完成后 resolve_binary 可用。"""
        if self.download.get("state") == "downloading":
            return
        def run():
            self.download = {"state": "downloading", "percent": 0, "error": ""}
            asset = self._asset_name()
            target = os.path.join(CFG.base_dir, "bin",
                                  "mihomo.exe" if os.name == "nt" else "mihomo")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            part, tmp = target + ".part", target + ".tmp"
            last_err = ""
            for mirror in MIHOMO_DOWNLOAD_MIRRORS:
                url = mirror + f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/{asset}"
                try:
                    with requests.get(url, stream=True, timeout=60,
                                      headers={"User-Agent": "muse2api"}) as r:
                        r.raise_for_status()
                        total = int(r.headers.get("Content-Length") or 0)
                        got = 0
                        with open(part, "wb") as f:
                            for chunk in r.iter_content(1 << 16):
                                got += len(chunk)
                                if got > _DOWNLOAD_MAX_BYTES:
                                    raise ValueError("下载超过 256MB 上限")
                                f.write(chunk)
                                if total:
                                    self.download["percent"] = min(99, got * 100 // total)
                    if asset.endswith(".zip"):
                        with zipfile.ZipFile(part) as z:
                            member = next(n for n in z.namelist()
                                          if n.lower().endswith(".exe") and "mihomo" in n.lower())
                            with z.open(member) as src, open(tmp, "wb") as dst:
                                dst.write(src.read())
                    else:
                        with gzip.open(part, "rb") as src, open(tmp, "wb") as dst:
                            dst.write(src.read())
                    os.replace(tmp, target)
                    try:
                        os.chmod(target, 0o755)
                    except OSError:
                        pass
                    for p in (part, tmp):
                        if os.path.exists(p):
                            os.unlink(p)
                    self.download = {"state": "done", "percent": 100, "error": ""}
                    self._wake.set()
                    return
                except Exception as exc:  # noqa: BLE001
                    last_err = str(exc)[:200]
                    for p in (part, tmp):
                        if os.path.exists(p):
                            try:
                                os.unlink(p)
                            except OSError:
                                pass
            self.download = {"state": "error", "percent": 0,
                             "error": f"下载失败：{last_err}（可手动下载 {self._asset_name()} 放到 {os.path.dirname(target)}）"}
        threading.Thread(target=run, daemon=True, name="mihomo-download").start()


    # ---------- 进程托管 ----------
    def is_running(self) -> bool:
        proc = self._proc
        if not proc or proc.poll() is not None:
            return False
        return self._controller_ok()

    def _controller_ok(self) -> bool:
        """external-controller /version + Bearer 探测（防止别的进程占着端口被误判）。"""
        try:
            r = requests.get(f"http://127.0.0.1:{self._api_port}/version",
                             headers={"Authorization": "Bearer " + self._api_secret},
                             timeout=1.0)
            data = r.json()
            return bool(data.get("version") or data.get("meta"))
        except Exception:  # noqa: BLE001
            return False

    def _preflight(self, ports: list[int]) -> str:
        for port in ports:
            try:
                s = socket.socket()
                s.bind(("127.0.0.1", port))
                s.close()
            except OSError:
                return f"端口 {port} 被占用，请释放或更换 base_port/api_port"
        return ""

    def apply(self, chain_entries: list[dict]) -> tuple[bool, str]:
        """生成配置并让 mihomo 收敛到期望状态；配置未变则跳过重启。"""
        with self._apply_lock:
            try:
                body, secret = self.build_yaml(chain_entries)
                binary = self.resolve_binary()
                if not self._enabled:
                    self._stop_process()
                    self._last_error = ""
                    return True, ""
                if not binary:
                    self._last_error = "未找到 mihomo 二进制：请点「下载」或手动放置到 bin/ 目录（或设置 MUSE2API_MIHOMO_PATH）"
                    return False, self._last_error
                if self.is_running() and body == self._last_yaml:
                    return True, ""          # 配置未变，跳过重启
                if self.is_running():
                    self._stop_process()     # 先停，避免 preflight 探到自己的端口
                err = self._preflight(sorted(set(self._port_map.values()) | {self._api_port}))
                if err:
                    self._last_error = err
                    return False, err
                os.makedirs(self.dir, exist_ok=True)
                with open(self.config_path, "wb") as f:
                    f.write(body)
                self._api_secret = secret
                self._last_yaml = body
                log = open(self.log_path, "ab")
                kwargs = {}
                if os.name == "nt":
                    kwargs["creationflags"] = 0x08000000   # CREATE_NO_WINDOW
                self._proc = subprocess.Popen(
                    [binary, "-d", self.dir, "-f", self.config_path],
                    stdout=log, stderr=log, **kwargs)
                self._running_pid = self._proc.pid
                if not self._wait_ready(self._proc, 6.0):
                    if self._proc.poll() is not None:
                        tail = self._log_tail()
                        err = (f"mihomo 启动即退出：{tail}" if tail
                               else f"mihomo 进程启动即退出（详见 {self.log_path}）")
                    else:
                        err = "mihomo 控制端口未就绪（超时 6s）"
                    self._last_error = err
                    self._stop_process()      # 别让看门狗反复重启一个坏配置
                    return False, err
                self._last_error = ""
                return True, ""
            except Exception as exc:  # noqa: BLE001
                self._last_error = f"应用失败：{exc}"
                return False, self._last_error

    def _log_tail(self, limit: int = 400) -> str:
        """抓 mihomo 日志最后一条 fatal/error，给 UI 显示真正的原因。"""
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 8192))
                text = f.read().decode(errors="replace")
        except OSError:
            return ""
        for line in reversed(text.splitlines()):
            low = line.lower()
            if "level=fatal" in low or "level=error" in low or "parse config error" in low:
                idx = line.find("msg=")
                msg = line[idx + 4:].strip().strip('"') if idx >= 0 else line.strip()
                return msg[:limit]
        return ""

    def _wait_ready(self, proc: subprocess.Popen, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                return False
            if self._controller_ok():
                return True
            time.sleep(0.25)
        # 超时不算失败：部分构建开端口慢，交给看门狗复核
        return self._controller_ok()

    def _stop_process(self):
        proc, self._proc, self._running_pid = self._proc, None, 0
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass

    def stop(self):
        self._wake.set()
        with self._apply_lock:
            self._stop_process()

    def start_if_enabled(self):
        if self._enabled:
            threading.Thread(target=self._apply_from_app, daemon=True,
                             name="mihomo-apply").start()
        threading.Thread(target=self._watch_loop, daemon=True,
                         name="mihomo-watcher").start()

    def _apply_from_app(self):
        """由 app 层注入 build 所需的池条目后执行 apply（见 app.py _mihomo_chain_entries）。"""
        fn = getattr(self, "_chain_entries_provider", None)
        return self.apply(fn() if fn else [])

    def set_chain_entries_provider(self, fn):
        self._chain_entries_provider = fn

    def request_apply(self):
        """配置变化后立即收敛（apply 内部有锁串行化 + unchanged 跳重启）。"""
        threading.Thread(target=self._apply_from_app, daemon=True,
                         name="mihomo-apply").start()

    def _watch_loop(self):
        """看门狗：桥启用但控制端口失联 → 自愈重启。
        连续失败按指数退避（60s→10min），配置错误不会每 60 秒刷一次日志。"""
        last_heal = 0.0
        backoff = 60.0
        while True:
            self._wake.wait(timeout=60)
            self._wake.clear()
            try:
                if self._enabled and not self.is_running() and self.resolve_binary():
                    if time.time() - last_heal >= backoff:
                        last_heal = time.time()
                        ok, err = self._apply_from_app()
                        if ok:
                            backoff = 60.0
                        else:
                            backoff = min(backoff * 2, 600.0)
                            log_msg = f"自愈失败，{int(backoff)}s 后重试：{err}"
                            self._last_error = log_msg
            except Exception as exc:  # noqa: BLE001
                self._last_error = f"看门狗异常：{exc}"


BRIDGE = MihomoBridge()


