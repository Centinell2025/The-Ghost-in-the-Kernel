#!/usr/bin/env python3
"""Create deterministic, entirely fictional Windows DFIR evidence.

Raw EVTX, memory images and actual malware are NOT included. Every file in
artifacts/ is a learning fixture, not a production acquisition or independent
witness. Does not execute code or contact a network.
"""
from __future__ import annotations
import csv
import hashlib
import json
import random
import shutil
import sqlite3
from datetime import datetime,timedelta,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"artifacts"
R=random.Random(100771)
START=datetime(2026,9,17,1,55,tzinfo=timezone.utc)
def stamp(n): return (START+timedelta(seconds=n)).isoformat(timespec="seconds").replace("+00:00","Z")
def csv_file(name,rows):
    columns=list(rows[0])
    with (OUT/name).open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,columns);w.writeheader();w.writerows(rows)
def write_jsonl(name,rows):
    with (OUT/name).open("w",encoding="utf-8") as f:
        for row in rows:f.write(json.dumps(row,sort_keys=True)+"\n")
def basic(n,kind,host):return dict(utc=stamp(n),host=host,event_id=f"BG-{kind}-{n:05d}")
def main():
    if OUT.is_symlink():raise RuntimeError("Refusing symlinked artifact directory")
    if OUT.exists():shutil.rmtree(OUT)
    OUT.mkdir()
    security=[]
    for i in range(58):
        row=basic(i*24,"SEC","nb-win-01")
        row.update(account=["svc-backup","nb-analyst","system"][i%3],source_ip=f"192.0.2.{25+i%25}",event_code=["4624","4634","4672"][i%3],logon_id=f"0x{0x2000+i:04x}",result="success",scope="synthetic-host-export")
        security.append(row)
    security.extend([
        dict(utc="2026-09-17T02:14:09Z",host="nb-win-01",event_id="SEC-401",
            account="svc-diagnostics",source_ip="192.0.2.44",event_code="4624",logon_id="0x7c2a",result="success",scope="synthetic-host-export"),
        dict(utc="2026-09-17T02:15:06Z",host="nb-win-01",event_id="SEC-402",
            account="svc-diagnostics",source_ip="192.0.2.44",event_code="4672",logon_id="0x7c2a",result="privilege-assigned",scope="synthetic-host-export")
    ])
    security.sort(key=lambda r:r["utc"]);csv_file("win_security.csv",security)
    processes=[]
    for i in range(94):
        row=basic(i*27,"PROC","nb-win-01")
        row.update(pid=str(1000+i),ppid="660",logon_id=f"0x{0x2000+i%58:04x}",image="C:\\Windows\\System32\\svchost.exe",command_line="svchost.exe -k benign",collector="synthetic-event-excerpt")
        processes.append(row)
    processes.extend([
        dict(utc="2026-09-17T02:17:05Z",host="nb-win-01",event_id="PROC-710",
             pid="1884",ppid="704",logon_id="0x7c2a",image="C:\\Windows\\System32\\taskeng.exe",
             command_line="taskeng.exe (scheduled activation)",collector="synthetic-event-excerpt"),
        dict(utc="2026-09-17T02:17:22Z",host="nb-win-01",event_id="PROC-711",
             pid="4320",ppid="1884",logon_id="0x7c2a",image="C:\\ProgramData\\Diag\\health-sync.exe",
             command_line="health-sync.exe --session telemetry",collector="synthetic-event-excerpt"),
        dict(utc="2026-09-17T02:18:32Z",host="nb-win-01",event_id="PROC-712",
             pid="4488",ppid="4320",logon_id="0x7c2a",image="C:\\Windows\\System32\\curl.exe",
             command_line="curl.exe https://status-check.example/api/health",collector="synthetic-event-excerpt")
    ])
    processes.sort(key=lambda r:r["utc"]);csv_file("sysmon_process.csv",processes)
    services=[]
    for i in range(25):
        row=basic(i*53,"SVC","nb-win-01")
        row.update(service=f"Service-{i:02d}",image_path="C:\\Windows\\System32\\svchost.exe",action=["inventory","health-check"][i%2],result="observed",collection="local-simulated")
        services.append(row)
    services.append(dict(utc="2026-09-17T02:17:18Z",host="nb-win-01",event_id="SVC-511",service="DiagHealthSvc",image_path="C:\\ProgramData\\Diag\\health-sync.exe",action="start-asserted",result="local-claim",collection="local-simulated"))
    services.sort(key=lambda r:r["utc"]);csv_file("services.csv",services)
    tasks=[]
    for i in range(29):
        row=basic(i*37,"TASK","nb-win-01")
        row.update(task_path=f"\\Microsoft\\Windows\\Maintenance\\Routine{i:02d}",command="rundll32.exe",action="observed",principal="SYSTEM")
        tasks.append(row)
    tasks.extend([
        dict(utc="2026-09-17T02:16:51Z",host="nb-win-01",event_id="TASK-611",
             task_path="\\Microsoft\\Windows\\Diagnostics\\TelemetryRefresh",command="C:\\ProgramData\\Diag\\health-sync.exe",action="registered",principal="svc-diagnostics"),
        dict(utc="2026-09-17T02:17:04Z",host="nb-win-01",event_id="TASK-612",
             task_path="\\Microsoft\\Windows\\Diagnostics\\TelemetryRefresh",command="C:\\ProgramData\\Diag\\health-sync.exe",action="trigger-asserted",principal="svc-diagnostics")
    ])
    tasks.sort(key=lambda r:r["utc"]);csv_file("scheduled_tasks.csv",tasks)
    views=[]
    for i in range(33):
        row=basic(i*38,"VIEW","nb-win-01")
        row.update(pid=str(1000+i),collector=["api-enumeration","event-excerpt"][i%2],visibility="listed",reason="sampled",provenance="not-independently-acquired")
        views.append(row)
    views.extend([
        dict(utc="2026-09-17T02:19:11Z",host="nb-win-01",event_id="VIEW-811",
             pid="4320",collector="api-enumeration",visibility="absent-from-sample",reason="sampling-or-visibility-unknown",provenance="not-independently-acquired"),
        dict(utc="2026-09-17T02:19:13Z",host="nb-win-01",event_id="VIEW-812",
             pid="4320",collector="event-excerpt",visibility="historically-recorded",reason="previous-process-create",provenance="not-independently-acquired"),
    ])
    views.sort(key=lambda r:r["utc"]);csv_file("process_visibility.csv",views)
    remote=[]
    for i in range(48):
        row=basic(i*41,"REMOTE","nb-file-02")
        row.update(account=["svc-backup","nb-analyst"][i%2],src_ip=f"192.0.2.{30+i%20}",event_code="4624",logon_id=f"0x{0x9000+i:x}",result="success")
        remote.append(row)
    remote.append(dict(utc="2026-09-17T02:21:10Z",host="nb-file-02",event_id="REMOTE-931",
                       account="svc-diagnostics",src_ip="192.0.2.16",event_code="4624",logon_id="0x99ce",result="success"))
    remote.sort(key=lambda r:r["utc"]);csv_file("file_server_security.csv",remote)
    dns=[]
    for i in range(47):
        row=basic(i*35,"DNS","nb-dns-01")
        row.update(client_ip=f"192.0.2.{20+i%28}",query=f"app{i:03d}.example",answer_ip=f"198.51.100.{20+i%49}",type="A")
        dns.append(row)
    dns.append(dict(utc="2026-09-17T02:18:24Z",host="nb-dns-01",event_id="DNS-911",client_ip="192.0.2.16",query="status-check.example",answer_ip="198.51.100.93",type="A"))
    dns.sort(key=lambda r:r["utc"]);csv_file("dns_queries.csv",dns)
    flows=[]
    for i in range(81):
        row=basic(i*29,"FLOW","nb-edge-01")
        row.update(src_ip=f"192.0.2.{30+i%28}",src_port=str(42000+i),dst_ip=f"198.51.100.{20+i%42}",dst_port=["80","443","53"][i%3],protocol=["TCP","TCP","UDP"][i%3],bytes_out=str(400+i*13),coverage="summary-only")
        flows.append(row)
    flows.append(dict(utc="2026-09-17T02:18:38Z",host="nb-edge-01",event_id="FLOW-951",
                      src_ip="192.0.2.16",src_port="50544",dst_ip="198.51.100.93",dst_port="443",protocol="TCP",bytes_out="14324",coverage="flow-summary-no-payload"))
    flows.sort(key=lambda r:r["utc"]);csv_file("network_flows.csv",flows)
    changes=[]
    for i in range(17):
        row=basic(i*95,"CHG","nb-change-01")
        row.update(ticket=f"CHG-{100+i}",target="nb-win-01" if i%2 else "nb-file-02",status=["approved","pending"][i%2],package=f"PKG-{i+20}",signature="simulation-assertion")
        changes.append(row)
    changes.extend([
        dict(utc="2026-09-17T02:11:00Z",host="nb-change-01",event_id="CHG-1011",ticket="CHG-782",target="nb-win-01",status="rejected",package="PKG-891",signature="unsigned"),
        dict(utc="2026-09-17T02:12:00Z",host="nb-change-01",event_id="CHG-1012",ticket="CHG-780",target="nb-win-01",status="approved",package="PKG-889",signature="claimed-signed")
    ])
    changes.sort(key=lambda r:r["utc"]);csv_file("change_control.csv",changes)
    clock=[
        dict(host="nb-win-01",source="sysmon_process.csv",offset_seconds="30",uncertainty_seconds="5",method="simulation-calibration"),
        dict(host="nb-file-02",source="file_server_security.csv",offset_seconds="-5",uncertainty_seconds="3",method="simulation-calibration"),
        dict(host="nb-edge-01",source="network_flows.csv",offset_seconds="2",uncertainty_seconds="10",method="simulation-calibration"),
    ]
    csv_file("clock_calibration.csv",clock)
    baseline=b"DIAG_HEALTH_POLICY=baseline\nAUTO_START=disabled\n"
    observed=b"DIAG_HEALTH_POLICY=modified\nAUTO_START=enabled\n"
    (OUT/"baseline_policy.bin").write_bytes(baseline)
    (OUT/"observed_policy.bin").write_bytes(observed)
    digests=[
      dict(utc="2026-09-17T02:00:00Z",host="nb-win-01",event_id="FIM-601",path="C:\\ProgramData\\Diag\\policy.dat",specimen="baseline_policy.bin",sha256=hashlib.sha256(baseline).hexdigest(),status="baseline"),
      dict(utc="2026-09-17T02:17:29Z",host="nb-win-01",event_id="FIM-602",path="C:\\ProgramData\\Diag\\policy.dat",specimen="observed_policy.bin",sha256=hashlib.sha256(observed).hexdigest(),status="changed"),
    ]
    csv_file("file_integrity.csv",digests)
    provenance=[]
    for name,host,scope in [
        ("win_security.csv","nb-win-01","selected-log-export"),
        ("sysmon_process.csv","nb-win-01","selected-event-excerpt"),
        ("services.csv","nb-win-01","selected-service-inventory"),
        ("scheduled_tasks.csv","nb-win-01","selected-task-report"),
        ("process_visibility.csv","nb-win-01","two-noncontemporaneous-collectors"),
        ("file_server_security.csv","nb-file-02","selected-log-export"),
        ("dns_queries.csv","nb-dns-01","selected-query-logs"),
        ("network_flows.csv","nb-edge-01","flow-summary-only"),
        ("change_control.csv","nb-change-01","simulated-approval-export"),
        ("file_integrity.csv","nb-win-01","local-software-hash-derived"),
        ("timeline_cache.sqlite3","derived-5-source-cache","not-independent"),
    ]:provenance.append(dict(artifact=name,source_host=host,scope=scope,independently_verified="no",contains_real_customer_data="no"))
    csv_file("acquisition_register.csv",provenance)
    db=sqlite3.connect(OUT/"timeline_cache.sqlite3")
    try:
        db.execute("CREATE TABLE observations (event_id TEXT PRIMARY KEY, timestamp_utc TEXT, source_artifact TEXT, host TEXT, actor TEXT, record_type TEXT, reference TEXT)")
        for filename,records,actor_key,reference_key in [
            ("win_security.csv",security,"account","logon_id"),
            ("sysmon_process.csv",processes,"image","pid"),
            ("scheduled_tasks.csv",tasks,"principal","task_path"),
            ("file_server_security.csv",remote,"account","logon_id"),
            ("network_flows.csv",flows,"src_ip","dst_ip"),
            ("change_control.csv",changes,"ticket","package"),
            ("file_integrity.csv",digests,"specimen","sha256"),
        ]:
            for row in records:
                db.execute("INSERT INTO observations VALUES (?,?,?,?,?,?,?)",(row["event_id"],row["utc"],filename,row["host"],row[actor_key],filename.split(".")[0],row[reference_key]))
        db.commit()
    finally:db.close()
    evidence=sorted(p for p in OUT.iterdir() if p.is_file())
    (OUT/"SHA256SUMS.txt").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in evidence),encoding="utf-8")
    print(f"Generated {len(evidence)} synthetic Windows DFIR exhibits and SHA-256 manifest")
if __name__=="__main__":main()
