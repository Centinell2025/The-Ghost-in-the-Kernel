#!/usr/bin/env python3
"""Validate deterministic simulated exhibits and packet/identity interpretation."""
import csv
import hashlib
import sqlite3
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
A=ROOT/"artifacts"
def require(ok,msg):
    if not ok:raise ValueError(msg)
def rows(file):
    with (A/file).open(encoding="utf-8",newline="") as f:return list(csv.DictReader(f))
def verify():
    manifest=(A/"SHA256SUMS.txt").read_text().splitlines()
    expected={}
    for line in manifest:
        digest,sep,name=line.partition("  ")
        require(sep and len(digest)==64 and name and "/" not in name and ".." not in name,"unsafe manifest item")
        require(name not in expected,"duplicate manifest name")
        expected[name]=digest
    present={p.name for p in A.iterdir() if p.is_file()}-{"SHA256SUMS.txt"}
    require(present==set(expected),"manifest misses evidence or includes stale file")
    for name,digest in expected.items():
        require(hashlib.sha256((A/name).read_bytes()).hexdigest()==digest,f"incorrect SHA256 for {name}")
    secs=rows("win_security.csv")
    procs=rows("sysmon_process.csv")
    tasks=rows("scheduled_tasks.csv")
    services=rows("services.csv")
    visible=rows("process_visibility.csv")
    remote=rows("file_server_security.csv")
    flows=rows("network_flows.csv")
    dns=rows("dns_queries.csv")
    changes=rows("change_control.csv")
    fim=rows("file_integrity.csv")
    clocks=rows("clock_calibration.csv")
    provenance=rows("acquisition_register.csv")
    require(len(secs)>55 and len(procs)>90 and len(flows)>80 and len(dns)>45,"insufficient benign-background records")
    keylog=[r for r in secs if r["account"]=="svc-diagnostics" and r["event_code"]=="4624" and r["logon_id"]=="0x7c2a"]
    require(len(keylog)==1 and keylog[0]["source_ip"]=="192.0.2.44","privilege-chain access ambiguous")
    active=[r for r in procs if r["pid"]=="4320" and r["ppid"]=="1884"]
    require(len(active)==1 and active[0]["logon_id"]==keylog[0]["logon_id"],"broken ancestry/login")
    child=[r for r in procs if r["ppid"]=="4320" and r["image"].endswith("curl.exe")]
    require(len(child)==1 and child[0]["logon_id"]==keylog[0]["logon_id"],"network client not linked to process")
    require(len([r for r in tasks if r["action"]=="registered" and "TelemetryRefresh" in r["task_path"]])==1,"task registration ambiguous")
    require(len([r for r in services if r["service"]=="DiagHealthSvc"])==1,"service ambiguous")
    for field,value in [("api-enumeration","absent-from-sample"),("event-excerpt","historically-recorded")]:
        require(len([r for r in visible if r["pid"]=="4320" and r["collector"]==field and r["visibility"]==value])==1,"process visibility contrast missing")
    require(any(r["account"]=="svc-diagnostics" and r["src_ip"]=="192.0.2.16" for r in remote),"file server lateral auth absent")
    flow=[r for r in flows if r["src_ip"]=="192.0.2.16" and r["dst_ip"]=="198.51.100.93"
          and r["dst_port"]=="443" and r["protocol"]=="TCP"]
    require(len(flow)==1 and flow[0]["bytes_out"]=="14324","network flow ambiguity")
    require(any(r["answer_ip"]==flow[0]["dst_ip"] and r["query"]=="status-check.example" for r in dns),"DNS/flow mismatch")
    require(any(r["ticket"]=="CHG-782" and r["status"]=="rejected" and r["signature"]=="unsigned" for r in changes),"change ticket failure")
    require(any(r["ticket"]=="CHG-780" and r["status"]=="approved" for r in changes),"legitimate maintenance decoy missing")
    require(len([r for r in fim if r["status"]=="changed"])==1,"FIM anomaly not unique")
    for row in fim:
        require(hashlib.sha256((A/row["specimen"]).read_bytes()).hexdigest()==row["sha256"],"FIM digest derived incorrectly")
    require(len({(r["host"],r["source"]) for r in clocks})==len(clocks),"ambiguous clock calibration")
    require(len(provenance)>=10 and all(r["independently_verified"]=="no" for r in provenance),"fictional source cannot be independently authenticated")
    with sqlite3.connect(f"file:{(A/'timeline_cache.sqlite3').resolve().as_posix()}?mode=ro",uri=True) as db:
        require(db.execute("PRAGMA quick_check").fetchone()[0]=="ok","broken sqlite")
        n=db.execute("SELECT count(*) FROM observations").fetchone()[0]
        p=db.execute("SELECT count(*) FROM observations WHERE event_id='PROC-711' AND reference='4320'").fetchone()[0]
        require(n>=300 and p==1,"SQLite cache missing key event")
    return dict(evidence_files=len(expected),records=n,questions=20,unverified_origins=len(provenance))
if __name__=="__main__":
    try:print("PASS Ghost DFIR evidence:",verify())
    except (OSError,ValueError,sqlite3.Error,KeyError,IndexError) as e:
        print("FAIL:",e,file=sys.stderr);sys.exit(1)
