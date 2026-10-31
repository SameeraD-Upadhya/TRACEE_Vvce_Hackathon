#!/usr/bin/env python3
"""Validate TRACEE synthetic CSV data and prepare parser-compatible replay batches.

Uses only Python's standard library. Optional HTTP upload targets TRACEE's existing
POST /api/v1/evidence multipart endpoint; it does not invoke the analysis API.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, random, re, sys, time, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FIELDS = [
    "record_id", "scenario_id", "correlation_id", "event_timestamp", "source_type",
    "host", "host_os", "channel", "provider", "event_code", "event_type", "severity",
    "outcome", "user", "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "process_name", "parent_process", "command_line", "file_path",
    "file_operation", "domain", "dns_query_type", "service_name", "service_action",
    "http_method", "url_path", "http_status", "bytes_sent", "bytes_received",
    "auth_method", "log_level", "message", "synthetic", "sequence_no"
]
SOURCE_TO_PARSER = {
    "linux_auth":"linux_auth", "systemd_journal":"systemd_journal",
    "windows_security":"windows_event", "windows_sysmon":"windows_event",
    "process_activity":"json_event", "network_flow":"json_event", "dns":"json_event",
    "filesystem":"json_event", "service_persistence":"json_event", "web_application":"json_event",
}
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ET.register_namespace("", NS)


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def parse_time(value: str) -> datetime:
    dt=datetime.fromisoformat(value.replace("Z","+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp is not timezone-aware: {value}")
    return dt.astimezone(timezone.utc)


def normalized_time(value: str) -> str:
    return parse_time(value).isoformat(timespec="microseconds").replace("+00:00","Z")


def to_auth_line(row: dict[str,str]) -> str:
    ts=parse_time(row["event_timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    event=re.sub(r"[^A-Za-z0-9_.-]","_",row["event_type"] or "auth_event")
    user=re.sub(r"\s+","_",row.get("user","") or "unknown")
    ip=row.get("source_ip","") or "0.0.0.0"
    return f"{ts} {event} user={user} ip={ip}\n"


def to_journal_line(row: dict[str,str]) -> str:
    dt=parse_time(row["event_timestamp"])
    epoch=datetime(1970,1,1,tzinfo=timezone.utc)
    delta=dt-epoch
    epoch_us=delta.days*86_400_000_000+delta.seconds*1_000_000+delta.microseconds
    host=row.get("host") or "TRACEE-LAB"
    unit=row.get("service_name") or "tracee-synthetic.service"
    pid=int(row.get("sequence_no") or "1") % 60000 + 100
    record={
        "__CURSOR":f"s=tracee-synthetic;i={row['record_id']};b=synthetic;m={pid};t={epoch_us};x=synthetic",
        "__REALTIME_TIMESTAMP":str(epoch_us),
        "__MONOTONIC_TIMESTAMP":str((pid*100000)+int(row.get("sequence_no") or 0)),
        "_BOOT_ID":"00000000000000000000000000000001",
        "MESSAGE":row.get("message") or row.get("event_type") or "synthetic journal entry",
        "PRIORITY":"4" if row.get("severity") in {"HIGH","CRITICAL"} else "6",
        "_SYSTEMD_UNIT":unit,"SYSLOG_IDENTIFIER":row.get("provider") or "tracee-synthetic",
        "_PID":str(pid),"_UID":"1000","_GID":"1000","_COMM":(row.get("process_name") or "synthetic")[:128],
        "_EXE":row.get("process_name") or "synthetic","_HOSTNAME":host,
    }
    return json.dumps(record,ensure_ascii=False,separators=(",",":"))+"\n"


def to_windows_envelope_line(row: dict[str,str]) -> str:
    event_id=int(row.get("event_code") or "1")
    if not 0 <= event_id <= 65535:
        event_id=1
    record_id=int(row.get("sequence_no") or "1")
    raw_time=normalized_time(row["event_timestamp"])
    provider=row.get("provider") or "TRACEE-Synthetic-Provider"
    channel=row.get("channel") or "System"
    host=row.get("host") or "TRACEE-WIN-LAB"
    root=ET.Element(f"{{{NS}}}Event")
    system=ET.SubElement(root,f"{{{NS}}}System")
    ET.SubElement(system,f"{{{NS}}}Provider",{"Name":provider})
    ET.SubElement(system,f"{{{NS}}}EventID").text=str(event_id)
    ET.SubElement(system,f"{{{NS}}}EventRecordID").text=str(record_id)
    ET.SubElement(system,f"{{{NS}}}TimeCreated",{"SystemTime":raw_time})
    ET.SubElement(system,f"{{{NS}}}Channel").text=channel
    ET.SubElement(system,f"{{{NS}}}Computer").text=host
    event_data=ET.SubElement(root,f"{{{NS}}}EventData")
    attrs=["event_type","severity","outcome","user","source_ip","destination_ip","process_name","parent_process","command_line","file_path","domain","message","scenario_id","correlation_id"]
    for name in attrs:
        value=row.get(name)
        if value:
            data=ET.SubElement(event_data,f"{{{NS}}}Data",{"Name":name})
            data.text=value[:2000]
    xml=ET.tostring(root,encoding="unicode",short_empty_elements=True)
    envelope={
        "schema_version":"1.0","source_type":"windows_event_log","host":host,"channel":channel,
        "provider":{"name":provider,"guid":None},"event_id":event_id,"record_id":record_id,
        "timestamp":{"raw":raw_time,"normalized_utc":raw_time},"event_xml":xml,
    }
    line=json.dumps(envelope,ensure_ascii=False,separators=(",",":"))+"\n"
    if len(line.encode("utf-8")) > 16*1024:
        raise ValueError(f"Windows event envelope too large for {row['record_id']}")
    return line


def to_json_event_line(row: dict[str,str]) -> str:
    attrs={k:v for k,v in row.items() if k not in {"event_timestamp","event_type"} and v not in (None,"")}
    payload={"timestamp":normalized_time(row["event_timestamp"]),"event_type":row["event_type"],"attributes":attrs}
    return json.dumps(payload,ensure_ascii=False,separators=(",",":"))+"\n"


def serialize_row(row: dict[str,str], source_id: str) -> str:
    parser=SOURCE_TO_PARSER[source_id]
    if parser=="linux_auth": return to_auth_line(row)
    if parser=="systemd_journal": return to_journal_line(row)
    if parser=="windows_event": return to_windows_envelope_line(row)
    return to_json_event_line(row)


def load_manifest(root: Path) -> dict:
    path=root/"dataset_manifest.json"
    if not path.is_file(): raise FileNotFoundError(f"Missing dataset manifest: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_corpus(root: Path, full_hash: bool=True) -> dict:
    manifest=load_manifest(root)
    total=0; results=[]; seen=set()
    for source in manifest["sources"]:
        path=root/source["csv_path"]
        if not path.is_file(): raise FileNotFoundError(path)
        if full_hash and sha256(path)!=source["sha256"]: raise ValueError(f"SHA-256 mismatch: {path.name}")
        with path.open("r",encoding="utf-8",newline="") as f:
            reader=csv.DictReader(f)
            if reader.fieldnames!=manifest["common_fields"]: raise ValueError(f"CSV header mismatch: {path.name}")
            count=0
            for row in reader:
                count+=1
                rid=row.get("record_id","")
                if not rid: raise ValueError(f"Blank record_id in {path.name} row {count+1}")
                if rid in seen: raise ValueError(f"Duplicate record_id: {rid}")
                seen.add(rid)
                if row.get("synthetic")!="true": raise ValueError(f"Record is not marked synthetic: {rid}")
                parse_time(row["event_timestamp"])
            if count!=source["record_count"]: raise ValueError(f"Record count mismatch: {path.name}: {count} != {source['record_count']}")
        total+=count; results.append({"source":source["id"],"records":count,"sha256_ok":True})
    if total!=manifest["total_records"]: raise ValueError("Total record count does not match manifest")
    truth=manifest["ground_truth_file"]; truth_path=root/truth["path"]
    if sha256(truth_path)!=truth["sha256"]: raise ValueError("Ground-truth SHA-256 mismatch")
    truth_count=0; truth_ids=set(); label_counts={}
    with truth_path.open("r",encoding="utf-8",newline="") as f:
        for row in csv.DictReader(f):
            truth_count+=1
            rid=row.get("record_id","")
            if rid not in seen: raise ValueError(f"Ground-truth references unknown record: {rid}")
            if rid in truth_ids: raise ValueError(f"Duplicate ground-truth record: {rid}")
            if row.get("label") not in {"SUSPICIOUS","MALICIOUS"}: raise ValueError(f"Invalid ground-truth label: {rid}")
            truth_ids.add(rid); label_counts[row["label"]]=label_counts.get(row["label"],0)+1
    if truth_count!=truth["record_count"]: raise ValueError("Ground-truth record count mismatch")
    profiles=manifest.get("scenario_profiles_file")
    profile_count=0
    if profiles:
        profile_path=root/profiles["path"]
        if sha256(profile_path)!=profiles["sha256"]: raise ValueError("Scenario profile catalog SHA-256 mismatch")
        profile_data=json.loads(profile_path.read_text(encoding="utf-8"))
        profile_count=len(profile_data.get("profiles",[]))
        if profile_count!=profiles["profile_count"]: raise ValueError("Scenario profile count mismatch")
    return {"status":"PASS","total_records":total,"positive_ground_truth_rows":truth_count,
            "ground_truth_label_counts":label_counts,"scenario_profile_count":profile_count,"sources":results}


def reservoir_rows(csv_path: Path, limit: int, rng: random.Random) -> list[dict[str,str]]:
    selected=[]
    with csv_path.open("r",encoding="utf-8",newline="") as f:
        reader=csv.DictReader(f)
        for i,row in enumerate(reader):
            if limit<=0:
                selected.append(row)
            elif len(selected)<limit:
                selected.append(row)
            else:
                j=rng.randint(0,i)
                if j<limit: selected[j]=row
    rng.shuffle(selected)
    return selected


def prepare_replay(root: Path, output: Path, seed: int, records_per_source: int, batch_size: int, only_sources: list[str] | None) -> dict:
    manifest=load_manifest(root)
    known={s["id"] for s in manifest["sources"]}
    chosen=set(only_sources or known)
    unknown=chosen-known
    if unknown: raise ValueError(f"Unknown sources: {sorted(unknown)}")
    run_id=f"REPLAY-{seed}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir=output/run_id; run_dir.mkdir(parents=True,exist_ok=False)
    batches=[]
    for source in manifest["sources"]:
        source_id=source["id"]
        if source_id not in chosen: continue
        srng=random.Random(seed ^ (sum(ord(c) for c in source_id)*65537))
        rows=reservoir_rows(root/source["csv_path"],records_per_source,srng)
        parser=SOURCE_TO_PARSER[source_id]
        ext=".log" if parser=="linux_auth" else ".jsonl"
        source_dir=run_dir/source_id; source_dir.mkdir()
        for batch_index,start in enumerate(range(0,len(rows),batch_size),start=1):
            chunk=rows[start:start+batch_size]
            filename=f"{source_id}-batch-{batch_index:04d}{ext}"
            path=source_dir/filename
            with path.open("w",encoding="utf-8",newline="") as f:
                for row in chunk: f.write(serialize_row(row,source_id))
            record_id_digest=hashlib.sha256("\n".join(row["record_id"] for row in chunk).encode("utf-8")).hexdigest()
            batches.append({"source_id":source_id,"parser_id":parser,"file":str(path.relative_to(run_dir)).replace("\\","/"),
                            "source_csv_sha256":source["sha256"],"record_count":len(chunk),"size_bytes":path.stat().st_size,"sha256":sha256(path),
                            "record_ids_sha256_in_replay_order":record_id_digest,
                            "record_id_first":chunk[0]["record_id"],"record_id_last":chunk[-1]["record_id"]})
        print(f"Prepared {source_id}: {len(rows):,} records in {(len(rows)+batch_size-1)//batch_size} batch(es)",flush=True)
    # Interleave batches from all selected source families into one deterministic replay queue.
    random.Random(seed ^ 0x5A17C3).shuffle(batches)
    for sequence,batch in enumerate(batches,start=1):
        batch["replay_sequence"]=sequence
    prepared={"schema_version":"1.0","run_id":run_id,"dataset_version":manifest["dataset_version"],"dataset_seed":manifest["generator_seed"],
              "dataset_manifest_sha256":sha256(root/"dataset_manifest.json"),
              "ground_truth_included":False,"replay_seed":seed,"selection":"random reservoir sample per source; records shuffled per source; source batches interleaved in one deterministic seeded queue",
              "records_per_source_limit":records_per_source,"batch_size":batch_size,"total_records":sum(b["record_count"] for b in batches),
              "batch_count":len(batches),"batches":batches,"synthetic":True,
              "note":"event timestamps are preserved; replay/acquisition timestamps must be recorded separately by the consuming simulation."}
    (run_dir/"replay_manifest.json").write_text(json.dumps(prepared,indent=2),encoding="utf-8")
    return {"run_dir":str(run_dir),"manifest":prepared}


def validate_with_tracee(run_dir: Path, tracee_root: Path) -> dict:
    src=tracee_root/"src"
    if not src.is_dir(): raise FileNotFoundError(f"TRACEE source directory not found: {src}")
    sys.path.insert(0,str(src))
    from parsers.registry import get_parsers
    parsers={p.name:p for p in get_parsers()}
    replay=json.loads((run_dir/"replay_manifest.json").read_text(encoding="utf-8"))
    output=[]
    for batch in replay["batches"]:
        parser_id=batch["parser_id"]
        if parser_id not in parsers: raise AssertionError(f"Parser missing from TRACEE registry: {parser_id}")
        p=parsers[parser_id]; path=run_dir/batch["file"]
        with path.open("r",encoding="utf-8") as f:
            sample=[]
            for _ in range(min(5,batch["record_count"])):
                line=f.readline()
                if not line: break
                sample.append(line)
        if not p.can_parse(path,sample): raise AssertionError(f"{parser_id} rejected {path.name}")
        parsed_count=0
        with path.open("r",encoding="utf-8") as f:
            for line_number,line in enumerate(f, start=1):
                if p.parse_line(line) is None:
                    raise AssertionError(f"{parser_id} failed to parse {path.name} line {line_number}")
                parsed_count+=1
        if parsed_count!=batch["record_count"]: raise AssertionError(f"Parsed line count mismatch in {path.name}")
        output.append({"file":batch["file"],"parser_id":parser_id,"records_checked":parsed_count,"can_parse":True,"parse_line":True})
    result={"status":"PASS","tracee_root":str(tracee_root.resolve()),"parser_ids_tested":sorted(set(x["parser_id"] for x in replay["batches"])),"batches_checked":len(output),"checks":output}
    (run_dir/"compatibility_report.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    return result


def upload_batches(run_dir: Path, api_url: str, token: str, analyze_after_upload: bool=False, delay_min_ms: int=0, delay_max_ms: int=0) -> dict:
    replay=json.loads((run_dir/"replay_manifest.json").read_text(encoding="utf-8"))
    results=[]
    pacing_rng=random.Random(replay.get("replay_seed",0) ^ 0x5A17C3)
    for idx,batch in enumerate(replay["batches"],start=1):
        path=run_dir/batch["file"]
        boundary="----TRACEEBoundary"+hashlib.sha256((str(path)+str(idx)).encode()).hexdigest()[:24]
        body=(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()+path.read_bytes()+f"\r\n--{boundary}--\r\n".encode()
        request=urllib.request.Request(api_url.rstrip("/")+"/api/v1/evidence",data=body,method="POST",headers={"Authorization":f"Bearer {token}","Content-Type":f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(request,timeout=120) as response:
                payload=json.loads(response.read().decode("utf-8"))
                item={"file":batch["file"],"parser_id":batch["parser_id"],"status":response.status,"evidence_id":payload.get("evidence_id"),"chain_sequence":payload.get("chain_sequence")}
                if analyze_after_upload and item.get("evidence_id"):
                    analyze_body=json.dumps({"parser":batch["parser_id"]}).encode("utf-8")
                    analyze_request=urllib.request.Request(
                        api_url.rstrip("/")+f"/api/v1/evidence/{item['evidence_id']}/analyze",
                        data=analyze_body,method="POST",
                        headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"},
                    )
                    try:
                        with urllib.request.urlopen(analyze_request,timeout=180) as analysis_response:
                            item["analysis_status"]=analysis_response.status
                            item["analysis"]=json.loads(analysis_response.read().decode("utf-8"))
                    except urllib.error.HTTPError as analysis_exc:
                        item["analysis_status"]=analysis_exc.code
                        item["analysis_error"]=analysis_exc.read(4096).decode("utf-8",errors="replace")
                        results.append(item)
                        break
                results.append(item)
        except urllib.error.HTTPError as exc:
            detail=exc.read(4096).decode("utf-8",errors="replace")
            results.append({"file":batch["file"],"parser_id":batch["parser_id"],"status":exc.code,"error":detail})
            break
        if idx < len(replay["batches"]) and delay_max_ms>0:
            time.sleep(pacing_rng.uniform(delay_min_ms,delay_max_ms)/1000.0)
    uploaded=sum(1 for x in results if 200<=x.get("status",0)<300)
    analyzed=sum(1 for x in results if 200<=x.get("analysis_status",0)<300)
    outcome={"api_url":api_url,"status":"COMPLETE" if uploaded==len(replay["batches"]) and (not analyze_after_upload or analyzed==uploaded) else "PARTIAL_OR_FAILED",
             "uploaded_batches":uploaded,"analyzed_batches":analyzed,"analysis_requested":analyze_after_upload,
             "delay_min_ms":delay_min_ms,"delay_max_ms":delay_max_ms,"attempted_batches":len(results),"results":results}
    (run_dir/"upload_report.json").write_text(json.dumps(outcome,indent=2),encoding="utf-8")
    return outcome


def main():
    ap=argparse.ArgumentParser(description="TRACEE synthetic CSV validation and replay adapter")
    sub=ap.add_subparsers(dest="command",required=True)
    v=sub.add_parser("validate",help="verify dataset counts, hashes, fields and uniqueness")
    v.add_argument("--dataset-root",type=Path,default=ROOT)
    v.add_argument("--no-hash",action="store_true")
    p=sub.add_parser("prepare",help="randomly sample and convert CSV rows to TRACEE parser-compatible batches")
    p.add_argument("--dataset-root",type=Path,default=ROOT)
    p.add_argument("--output",type=Path,default=ROOT/"replay_runs")
    p.add_argument("--seed",type=int,default=42)
    p.add_argument("--records-per-source",type=int,default=5000,help="0 means all records in each selected source")
    p.add_argument("--batch-size",type=int,default=5000)
    p.add_argument("--sources",nargs="*",default=None)
    p.add_argument("--tracee-root",type=Path,default=None)
    u=sub.add_parser("upload",help="upload prepared replay batches to a running TRACEE API")
    u.add_argument("--run-dir",type=Path,required=True)
    u.add_argument("--api-url",default="http://127.0.0.1:8000")
    u.add_argument("--api-token",default=os.environ.get("TRACEE_API_TOKEN"))
    u.add_argument("--analyze",action="store_true",help="after upload, call the existing analyze endpoint using each batch's mapped parser_id")
    u.add_argument("--delay-min-ms",type=int,default=0,help="minimum random delay between batch uploads")
    u.add_argument("--delay-max-ms",type=int,default=0,help="maximum random delay between batch uploads")
    args=ap.parse_args()
    if args.command=="validate":
        print(json.dumps(validate_corpus(args.dataset_root.resolve(),not args.no_hash),indent=2))
    elif args.command=="prepare":
        if args.records_per_source<0 or args.batch_size<1: ap.error("records-per-source must be >=0 and batch-size >=1")
        result=prepare_replay(args.dataset_root.resolve(),args.output.resolve(),args.seed,args.records_per_source,args.batch_size,args.sources)
        print(json.dumps({"run_dir":result["run_dir"],"records":result["manifest"]["total_records"],"batches":result["manifest"]["batch_count"]},indent=2))
        if args.tracee_root:
            print(json.dumps(validate_with_tracee(Path(result["run_dir"]),args.tracee_root.resolve()),indent=2))
    elif args.command=="upload":
        if not args.api_token or len(args.api_token)<32: ap.error("provide --api-token or TRACEE_API_TOKEN (minimum 32 characters)")
        if args.delay_min_ms<0 or args.delay_max_ms<args.delay_min_ms: ap.error("delay values must satisfy 0 <= min <= max")
        print(json.dumps(upload_batches(args.run_dir.resolve(),args.api_url,args.api_token,args.analyze,args.delay_min_ms,args.delay_max_ms),indent=2))

if __name__=="__main__": main()
