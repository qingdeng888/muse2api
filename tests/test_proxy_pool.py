"""ProxyPool 纯逻辑单测：去重 / 轮询游标 / 故障转移挑选 / 健康转移，无网络。

运行: venv/python tests/test_proxy_pool.py
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_tmp = tempfile.TemporaryDirectory(prefix="muse-pool-test-")
from pool import ProxyPool, proxy_id

_counter = {"n": 0}


def fresh_pool():
    _counter["n"] += 1
    return ProxyPool(path=str(Path(_tmp.name) / f"proxies-{_counter['n']}.json"))


def test_add_dedupe_and_persistence():
    p = fresh_pool()
    a, created1 = p.add("socks5://u1:pw@10.0.0.1:1080", label="one")
    assert created1 and a["server"] == "socks5://10.0.0.1:1080" and a["username"] == "u1"
    b, created2 = p.add({"server": "socks5://10.0.0.1:1080", "username": "u1", "password": "other"})
    assert not created2 and b["id"] == a["id"], "同 server+username 视为同一代理"
    c, _ = p.add("socks5://10.0.0.1:1080")
    assert c["id"] != a["id"], "同地址不同凭据是不同代理"
    # 持久化：新实例读回同一文件
    p2 = ProxyPool(path=p.path)
    assert {i["id"] for i in p2.entries()} == {a["id"], c["id"]}
    assert p2.get(a["id"])["label"] == "one"
    print("PASS: add/dedupe/persistence")


def test_bulk_and_validation():
    p = fresh_pool()
    text = "\n".join([
        "# comment line",
        "http://10.0.1.1:8080",
        "http://10.0.1.1:8080",          # 重复
        "socks5://10.0.1.2:1080",
        "ftp://bad.example:21",          # 非法协议
    ])
    res = p.bulk_add(text)
    assert res["added"] == 2 and res["skipped"] == 1, res
    assert len(res["errors"]) == 1
    print("PASS: bulk import dedupe/validation")


def test_rotate_cursor():
    p = fresh_pool()
    ids = []
    for i in range(3):
        e, _ = p.add(f"http://10.1.0.{i}:80")
        ids.append(e["id"])
    seq = [p.next_healthy()["id"] for _ in range(4)]
    assert seq[:3] == ids and seq[3] == ids[0], f"轮询顺序错误: {seq}"
    # 标记一个不健康 → 跳过
    p.mark_result(ids[1], False, error="down")
    seq2 = [p.next_healthy()["id"] for _ in range(3)]
    assert ids[1] not in seq2 and len(seq2) == 3, seq2
    # 全部不健康 → 仍返回游标位（fail-closed，失败可见）
    for i in ids:
        p.mark_result(i, False)
    got = p.next_healthy()
    assert got is not None and got["id"] in ids, "全挂时必须仍返回候选而非 None"
    # 空 / 全停用 → None
    for i in ids:
        p.update(i, enabled=False)
    assert p.next_healthy() is None
    print("PASS: rotate cursor / skip unhealthy / fail-closed / empty")


def test_failover_pick():
    p = fresh_pool()
    e = {}
    for i in range(4):
        e[i], _ = p.add(f"socks5://10.2.0.{i}:1080")
    counts = {e[1]["id"]: 2, e[2]["id"]: 1}   # e[3] 零绑定
    # 排除 home(e0) 后：零绑定健康者优先
    pick = p.failover_pick(exclude_id=e[0]["id"], bind_counts=counts)
    assert pick["id"] == e[3]["id"], "优先零绑定健康代理"
    # 没有零绑定候选 → 最少绑定者
    pick2 = p.failover_pick(exclude_id=e[0]["id"],
                            bind_counts={e[1]["id"]: 1, e[2]["id"]: 1, e[3]["id"]: 2})
    assert pick2["id"] == e[1]["id"], "同为 1 绑定时按配置顺序取首个健康者"
    # 健康的只剩 2 号（1 号与 3 号都挂）→ 选中 2 号
    p.mark_result(e[1]["id"], False, error="down")
    p.mark_result(e[3]["id"], False, error="down")
    pick3 = p.failover_pick(exclude_id=e[0]["id"], bind_counts=counts)
    assert pick3["id"] == e[2]["id"]
    # 全不健康 → 仍返回启用者（可见失败优于直连）
    p.mark_result(e[2]["id"], False, error="down")
    p.mark_result(e[3]["id"], False, error="down")
    pick4 = p.failover_pick(exclude_id=e[0]["id"], bind_counts=counts)
    assert pick4 is not None and pick4["id"] != e[0]["id"]
    # 仅剩排除项 → None
    for i in (1, 2, 3):
        p.update(e[i]["id"], enabled=False)
    assert p.failover_pick(exclude_id=e[0]["id"]) is None
    print("PASS: failover preference (zero-binding healthy → least-bound → visible failure)")


def test_health_transitions_and_restore():
    p = fresh_pool()
    e, _ = p.add("http://10.3.0.1:8080")
    assert p.is_healthy(e["id"]) is True, "乐观初始健康"
    p.mark_result(e["id"], False, error="timeout")
    assert p.is_healthy(e["id"]) is False
    assert p.health(e["id"])["last_error"] == "timeout"
    # 恢复：成功即回家（延迟与出口 IP 记录）
    p.mark_result(e["id"], True, latency_ms=233.6, exit_ip="198.51.100.7")
    h = p.health(e["id"])
    assert p.is_healthy(e["id"]) is True
    assert h["latency_ms"] == 234 and h["exit_ip"] == "198.51.100.7" and h["last_error"] == ""
    # 检测互斥认领
    assert p.start_check(e["id"]) is True
    assert p.start_check(e["id"]) is False
    p.mark_result(e["id"], True)
    assert p.health(e["id"])["checking"] is False
    # 未入库的 id 不产生运行态
    p.mark_result("nonexistent", False)
    print("PASS: health transitions / restore / check claim")


def test_delete_and_update():
    p = fresh_pool()
    a, _ = p.add("socks5://10.4.0.1:1080", label="keep")
    b, _ = p.add("socks5://10.4.0.2:1080", label="gone")
    p.update(b["id"], password="new-secret", label="renamed")
    assert p.get(b["id"])["label"] == "renamed"
    snap = p.snapshot(bind_counts={a["id"]: 3})
    row_a = next(r for r in snap if r["id"] == a["id"])
    row_b = next(r for r in snap if r["id"] == b["id"])
    assert row_a["bindings"] == 3
    assert row_b["has_password"] is True and row_b["label"] == "renamed"
    assert "new-secret" not in json.dumps(snap), "快照绝不能泄漏密码"
    assert p.remove(b["id"]) is True and p.get(b["id"]) is None
    assert p.remove(b["id"]) is False
    print("PASS: update/remove/redacted snapshot")


if __name__ == "__main__":
    test_add_dedupe_and_persistence()
    test_bulk_and_validation()
    test_rotate_cursor()
    test_failover_pick()
    test_health_transitions_and_restore()
    test_delete_and_update()
    print("ALL POOL TESTS PASSED")
