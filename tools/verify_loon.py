#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loon 配置校验（独立可复现）
用法: python verify_loon.py <loon.conf>
依赖: 仅标准库
"""
import sys, re, json, time, urllib.request, urllib.parse, concurrent.futures

def fetch(url, tries=3):
    q = urllib.parse.quote(url, safe=":/@?&=%#[]!$'()*+,;~")
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(q, headers={"User-Agent": "Loon/3"})
            with urllib.request.urlopen(req, timeout=40) as r:
                return r.read(), r.status
        except Exception as e:
            last = e
            if i < tries - 1:
                time.sleep(1)
    raise last

def main(path):
    t = open(path, encoding="utf-8").read()
    sec, cur = {}, None
    for l in t.split("\n"):
        m = re.match(r"^\[(.+)\]$", l)
        if m:
            cur = m.group(1); sec[cur] = []
        elif cur is not None:
            sec[cur].append(l)
    res = []
    def chk(no, name, ok, detail=""):
        res.append({"no": no, "assert": name, "result": "PASS" if ok else "FAIL", "detail": detail})

    need = ["General", "Proxy", "Proxy Group", "Rule", "Plugin", "MITM"]
    chk(1, "分段完整", all(k in sec for k in need),
        ",".join(k for k in need if k not in sec) or "7 段齐全")
    groups = {l.split(" = ")[0].strip() for l in sec.get("Proxy Group", []) if " = " in l}
    known = groups | {"DIRECT", "REJECT", "P1", "P2"}
    rules = [l for l in sec.get("Rule", []) if l and "," in l]
    dang = 0
    for l in rules:
        p = [x.strip() for x in l.split(",")]
        pol = p[1] if p[0] == "FINAL" else (p[2] if len(p) > 2 else None)
        if pol and pol not in known:
            dang += 1
    chk(2, "无悬空策略引用", dang == 0, "%d 条" % dang)
    seen, dup = set(), 0
    for l in rules:
        if l in seen: dup += 1
        seen.add(l)
    chk(3, "显式规则无重复", dup == 0, "%d 条" % dup)
    plugins = [(l.split(" = ")[0], l.split(" = ")[1].split(",")[0].strip())
               for l in sec.get("Plugin", []) if " = https://" in l]
    en = [x for x in plugins if "enabled=true" in x[1] or ", enabled=true" in x[1]]
    def probe(item):
        n, u = item
        try:
            raw, code = fetch(u)
            return (n, code == 200 and len(raw) > 5)
        except Exception:
            return (n, False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        pr = list(ex.map(probe, plugins))
    pbad = [x for x in pr if not x[1]]
    chk(4, "插件全部可下载", not pbad, "%d/%d" % (len(pr) - len(pbad), len(pr)))
    rsets = [l.split(",")[1] for l in rules if l.startswith("RULE-SET,")]
    def prs(u):
        try:
            raw, code = fetch(u)
            return code == 200 and len(raw) > 5
        except Exception:
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        sr = list(ex.map(prs, rsets))
    chk(5, "规则集全部可下载", all(sr), "%d/%d" % (sum(1 for x in sr if x), len(sr)))
    chk(6, "main/master 漂移", "@main" not in t and "releases/latest" not in t,
        "main:%d latest:%d" % (t.count("@main"), t.count("releases/latest")))
    token = any(x in t for x in ("OwO=", "gfwairport"))
    chk(7, "分享版无明文 token", "脱敏" not in path or not token, "token=%s" % token)
    ok = all(x["result"] == "PASS" for x in res)
    print("%-3s %-30s %-6s %s" % ("#", "断言", "结果", "实测"))
    for x in res:
        print("%-3s %-30s %-6s %s" % (x["no"], x["assert"], x["result"], x["detail"][:55]))
    print("全部通过:", ok)
    json.dump({"config": path, "all_pass": ok, "assertions": res},
              open("verify-loon-report.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    main(sys.argv[1])
