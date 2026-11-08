"""集中式代理池：供 muse 账号绑定（bind）/ 轮询（rotate）使用。

设计对齐 opencode2api 的上游代理池：
- 持久层只存代理本体（server/username/password/enabled/label），健康、延迟、
  绑定计数等运行态全部在内存里，进程重启后乐观重置为健康（首次失败即纠正）。
- 代理 ID = sha256(f"{server}|{username}")[:16]，凭据不同视为不同代理。
- 轮询：共享游标每次推进一格，取第一个健康者；全部不健康时仍返回游标位
  （fail-closed，让失败可见，绝不静默直连）。
- 故障转移：解析是无状态的——把故障代理标记为不健康后，下一次解析自然落到
  替补；代理恢复健康后同样自动"回家"。所以这里只需要状态与挑选算法，
  不需要任何账号级迁移记录。
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time

from config import CFG
from proxy import normalize_server, split_proxy_url


def proxy_id(server: str, username: str = "") -> str:
    value = f"{(server or '').strip()}|{(username or '').strip()}"
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class ProxyPool:
    """data/proxies.json 的读写 + 内存运行态。线程安全。"""

    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(CFG.data_dir, "proxies.json")
        self._lock = threading.RLock()
        self._items: list[dict] = []
        self._cursor = 0
        # 运行态：pid -> {healthy, latency_ms, exit_ip, last_check, last_error, checking}
        self._rt: dict[str, dict] = {}
        self._load()

    # ---------------- 持久化 ----------------
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            items = data.get("proxies") if isinstance(data, dict) else None
            if isinstance(items, list):
                self._items = [i for i in items if isinstance(i, dict) and i.get("server")]
        except (OSError, ValueError):
            self._items = []
        for item in self._items:
            item.setdefault("enabled", True)
            self._rt.setdefault(item["id"], self._fresh_rt())

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"proxies": self._items}, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    @staticmethod
    def _fresh_rt() -> dict:
        # 乐观初始：新代理视为健康，直到真实流量或检测证明相反
        return {"healthy": True, "latency_ms": None, "exit_ip": None,
                "last_check": 0, "last_error": "", "checking": False}

    # ---------------- 基础 CRUD ----------------
    def entries(self) -> list[dict]:
        with self._lock:
            return [dict(i) for i in self._items]

    def get(self, pid: str | None) -> dict | None:
        if not pid:
            return None
        with self._lock:
            for i in self._items:
                if i["id"] == pid:
                    return dict(i)
        return None

    def add(self, value: str | dict, label: str = "",
            username: str = "", password: str = "") -> tuple[dict, bool]:
        """新增代理。value 可以是完整链接（支持 user:pass@host）或 {server,...}。
        返回 (条目, 是否新建)；重复添加返回已存在条目。"""
        if isinstance(value, str):
            cfg = split_proxy_url({"server": value.strip()})
        elif isinstance(value, dict):
            cfg = split_proxy_url(dict(value))
        else:
            raise ValueError("invalid proxy value")
        if username:
            cfg["username"] = username
        if password:
            cfg["password"] = password
        # split_proxy_url 只在凭据内嵌时拆分，不校验协议；这里强制规范化（http/socks5/socks5h）
        cfg["server"] = normalize_server(cfg["server"])
        server = cfg["server"]
        user = cfg.get("username") or ""
        pid = proxy_id(server, user)
        with self._lock:
            for i in self._items:
                if i["id"] == pid:
                    return dict(i), False
            entry = {"id": pid, "server": server, "username": user,
                     "password": cfg.get("password") or "",
                     "label": (label or "").strip(), "enabled": True,
                     "created_at": int(time.time())}
            self._items.append(entry)
            self._rt.setdefault(pid, self._fresh_rt())
            self._save()
            return dict(entry), True

    def bulk_add(self, text: str) -> dict:
        added = skipped = 0
        errors: list[str] = []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                _, created = self.add(line)
                added += 1 if created else 0
                skipped += 0 if created else 1
            except (ValueError, KeyError) as exc:
                errors.append(f"{line[:60]}: {exc}")
        return {"added": added, "skipped": skipped, "errors": errors}

    def update(self, pid: str, password: str | None = None,
               label: str | None = None, enabled: bool | None = None) -> dict | None:
        with self._lock:
            for i in self._items:
                if i["id"] == pid:
                    if password is not None:
                        i["password"] = password
                    if label is not None:
                        i["label"] = label.strip()
                    if enabled is not None:
                        i["enabled"] = bool(enabled)
                        if not i["enabled"]:
                            self._rt.setdefault(pid, self._fresh_rt())["healthy"] = False
                    self._save()
                    return dict(i)
        return None

    def remove(self, pid: str) -> bool:
        with self._lock:
            before = len(self._items)
            self._items = [i for i in self._items if i["id"] != pid]
            changed = len(self._items) != before
            if changed:
                self._rt.pop(pid, None)
                self._save()
            return changed

    # ---------------- 运行态 / 健康 ----------------
    def mark_result(self, pid: str, ok: bool, latency_ms: float | None = None,
                    exit_ip: str | None = None, error: str = ""):
        if not pid or pid not in {i["id"] for i in self._items}:
            return
        with self._lock:
            rt = self._rt.setdefault(pid, self._fresh_rt())
            rt["checking"] = False
            rt["last_check"] = int(time.time())
            if ok:
                rt["healthy"] = True
                rt["last_error"] = ""
                if latency_ms is not None:
                    rt["latency_ms"] = round(float(latency_ms))
                if exit_ip:
                    rt["exit_ip"] = exit_ip
            else:
                rt["healthy"] = False
                rt["last_error"] = (error or "proxy check failed")[:200]

    def start_check(self, pid: str) -> bool:
        """认领一次检测（防并发重复检测）。"""
        with self._lock:
            rt = self._rt.setdefault(pid, self._fresh_rt())
            if rt.get("checking"):
                return False
            rt["checking"] = True
            return True

    def health(self, pid: str) -> dict:
        with self._lock:
            return dict(self._rt.get(pid) or self._fresh_rt())

    def is_healthy(self, pid: str) -> bool:
        return bool(self.health(pid).get("healthy", True))

    # ---------------- 挑选算法 ----------------
    def next_healthy(self, advance: bool = True) -> dict | None:
        """轮询：游标推进一格取第一个健康者；全部不健康仍返回游标位（失败可见）。"""
        with self._lock:
            pool = [i for i in self._items if i.get("enabled", True)]
            if not pool:
                return None
            n = len(pool)
            picked = None
            for off in range(n):
                idx = (self._cursor + off) % n
                if self._rt.get(pool[idx]["id"], self._fresh_rt()).get("healthy", True):
                    picked = idx
                    break
            if picked is None:
                picked = self._cursor % n      # 全挂：返回游标位，让尝试失败可见
            if advance:
                self._cursor = (picked + 1) % n
            return dict(pool[picked])

    def failover_pick(self, exclude_id: str | None = None,
                      bind_counts: dict[str, int] | None = None) -> dict | None:
        """故障转移替补：零绑定健康者 → 最少绑定健康者 → 任意启用者（含不健康，宁可可见失败）。"""
        with self._lock:
            pool = [i for i in self._items
                    if i.get("enabled", True) and i["id"] != exclude_id]
            if not pool:
                return None
            counts = bind_counts or {}
            healthy = [i for i in pool if self._rt.get(i["id"], self._fresh_rt()).get("healthy", True)]
            if healthy:
                zero = [i for i in healthy if not counts.get(i["id"])]
                if zero:
                    return dict(zero[0])
                return dict(min(healthy, key=lambda i: counts.get(i["id"], 0)))
            return dict(pool[0])               # 全不健康也给出目标，失败可见优于静默直连

    # ---------------- API 视图 ----------------
    def snapshot(self, bind_counts: dict[str, int] | None = None) -> list[dict]:
        with self._lock:
            counts = bind_counts or {}
            out = []
            for i in self._items:
                rt = self._rt.get(i["id"], self._fresh_rt())
                out.append({"id": i["id"], "server": i["server"],
                            "username": i.get("username") or "",
                            "has_password": bool(i.get("password")),
                            "label": i.get("label") or "",
                            "enabled": i.get("enabled", True),
                            "created_at": i.get("created_at"),
                            "healthy": rt.get("healthy", True),
                            "checking": rt.get("checking", False),
                            "latency_ms": rt.get("latency_ms"),
                            "exit_ip": rt.get("exit_ip"),
                            "last_check": rt.get("last_check"),
                            "last_error": rt.get("last_error") or "",
                            "bindings": counts.get(i["id"], 0)})
            return out


POOL = ProxyPool()
