#!/usr/bin/env python3
"""Generate a deterministic, entirely synthetic multi-source TRACEE corpus."""
from __future__ import annotations
import argparse, csv, hashlib, json, random, string
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0.0"
SEED_DEFAULT = 20261030
START = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 10, 30, 23, 59, tzinfo=timezone.utc)

FIELDS = [
    "record_id", "scenario_id", "correlation_id", "event_timestamp", "source_type",
    "host", "host_os", "channel", "provider", "event_code", "event_type", "severity",
    "outcome", "user", "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "process_name", "parent_process", "command_line", "file_path",
    "file_operation", "domain", "dns_query_type", "service_name", "service_action",
    "http_method", "url_path", "http_status", "bytes_sent", "bytes_received",
    "auth_method", "log_level", "message", "synthetic", "sequence_no"
]

SOURCES = [
    {"id":"linux_auth", "file":"linux_auth.csv", "count":90000, "parser_id":"linux_auth", "source_type":"linux_auth", "host_os":"linux", "description":"SSH, PAM, sudo and account authentication events"},
    {"id":"systemd_journal", "file":"systemd_journal.csv", "count":75000, "parser_id":"systemd_journal", "source_type":"systemd_journal", "host_os":"linux", "description":"systemd service, kernel, daemon and system journal records"},
    {"id":"windows_security", "file":"windows_security.csv", "count":95000, "parser_id":"windows_event", "source_type":"windows_event_log", "host_os":"windows", "description":"Windows Security channel authentication, account and privilege events"},
    {"id":"windows_sysmon", "file":"windows_sysmon.csv", "count":100000, "parser_id":"windows_event", "source_type":"windows_event_log", "host_os":"windows", "description":"Sysmon process, network, image-load, file and DNS telemetry"},
    {"id":"process_activity", "file":"process_activity.csv", "count":70000, "parser_id":"json_event", "source_type":"process_activity", "host_os":"mixed", "description":"Normalized process start, exit, parent-child and execution observations"},
    {"id":"network_flow", "file":"network_flow.csv", "count":75000, "parser_id":"json_event", "source_type":"network_flow", "host_os":"mixed", "description":"Synthetic connection metadata and byte-count network flow records"},
    {"id":"dns", "file":"dns.csv", "count":55000, "parser_id":"json_event", "source_type":"dns", "host_os":"mixed", "description":"DNS query and response records with safe reserved domains"},
    {"id":"filesystem", "file":"filesystem.csv", "count":60000, "parser_id":"json_event", "source_type":"filesystem", "host_os":"mixed", "description":"File create, read, modify, rename and delete audit events"},
    {"id":"service_persistence", "file":"service_persistence.csv", "count":55000, "parser_id":"json_event", "source_type":"service_persistence", "host_os":"mixed", "description":"Service, scheduled task, startup and persistence configuration events"},
    {"id":"web_application", "file":"web_application.csv", "count":75000, "parser_id":"json_event", "source_type":"web_application", "host_os":"linux", "description":"HTTP access, authentication, validation and application error records"},
]

HOSTS = [f"WIN-{i:03d}" for i in range(1, 81)] + [f"LINUX-{i:03d}" for i in range(1, 61)]
USERS = ["administrator", "svc_backup", "svc_web", "analyst01", "jdoe", "asmith", "buildsvc", "dbadmin", "guest", "deploy"]
PRIVATE_IPS = [f"10.{20+i%12}.{(i*7)%250+1}.{(i*13)%250+1}" for i in range(100)]
DOC_IPS = [f"192.0.2.{i}" for i in range(10, 240)] + [f"198.51.100.{i}" for i in range(10, 240)] + [f"203.0.113.{i}" for i in range(10, 240)]
DOMAINS = [f"service-{i:03d}.example" for i in range(1, 150)] + [f"node-{i:03d}.test" for i in range(1, 150)]
PROCESSES = ["svchost.exe", "services.exe", "explorer.exe", "powershell.exe", "cmd.exe", "python.exe", "sshd", "sudo", "nginx", "systemd", "chrome.exe", "w3wp.exe"]

PROFILES = {
    "credential_abuse": [
        ("linux_auth","ssh_failed","SUSPICIOUS","T1110","credential_access"),
        ("linux_auth","ssh_failed","SUSPICIOUS","T1110","credential_access"),
        ("windows_security","logon_failure","SUSPICIOUS","T1110","credential_access"),
        ("windows_security","logon_success","MALICIOUS","T1078","initial_access"),
        ("network_flow","remote_admin_connection","MALICIOUS","T1021","lateral_movement"),
        ("windows_sysmon","process_create","MALICIOUS","T1059","execution"),
        ("process_activity","interactive_shell_start","MALICIOUS","T1059","execution"),
        ("dns","internal_service_lookup","BENIGN","","discovery"),
        ("systemd_journal","sshd_auth_notice","SUSPICIOUS","T1021","lateral_movement"),
    ],
    "privilege_escalation": [
        ("linux_auth","sudo_elevation","MALICIOUS","T1548","privilege_escalation"),
        ("systemd_journal","privileged_service_action","SUSPICIOUS","T1548","privilege_escalation"),
        ("windows_security","special_privileges_assigned","MALICIOUS","T1134","privilege_escalation"),
        ("windows_sysmon","process_create","MALICIOUS","T1059","execution"),
        ("process_activity","elevated_process_start","MALICIOUS","T1068","privilege_escalation"),
        ("filesystem","protected_config_read","SUSPICIOUS","T1005","collection"),
        ("service_persistence","service_config_change","SUSPICIOUS","T1543","persistence"),
    ],
    "suspicious_execution": [
        ("windows_sysmon","process_create","MALICIOUS","T1059","execution"),
        ("windows_sysmon","image_load","SUSPICIOUS","T1129","execution"),
        ("process_activity","unusual_parent_child","MALICIOUS","T1059","execution"),
        ("process_activity","script_interpreter_start","SUSPICIOUS","T1059","execution"),
        ("network_flow","outbound_connection","SUSPICIOUS","T1071","command_and_control"),
        ("dns","rare_domain_lookup","SUSPICIOUS","T1071","command_and_control"),
        ("filesystem","temporary_file_create","SUSPICIOUS","T1105","command_and_control"),
        ("systemd_journal","application_warning","BENIGN","","execution"),
    ],
    "dns_anomaly": [
        ("dns","high_entropy_subdomain","MALICIOUS","T1071.004","command_and_control"),
        ("dns","repeated_nxdomain","SUSPICIOUS","T1071.004","command_and_control"),
        ("dns","rare_domain_lookup","SUSPICIOUS","T1071.004","command_and_control"),
        ("network_flow","small_periodic_outbound_flow","SUSPICIOUS","T1071","command_and_control"),
        ("windows_sysmon","dns_query","SUSPICIOUS","T1071.004","command_and_control"),
        ("process_activity","background_client_start","BENIGN","","command_and_control"),
    ],
    "persistence_change": [
        ("service_persistence","service_install","MALICIOUS","T1543","persistence"),
        ("service_persistence","scheduled_task_create","SUSPICIOUS","T1053","persistence"),
        ("windows_security","account_change","SUSPICIOUS","T1098","persistence"),
        ("windows_sysmon","registry_value_set","MALICIOUS","T1547","persistence"),
        ("filesystem","startup_config_write","MALICIOUS","T1547","persistence"),
        ("systemd_journal","service_started","SUSPICIOUS","T1543","persistence"),
        ("process_activity","service_child_process","SUSPICIOUS","T1543","persistence"),
    ],
    "lateral_movement": [
        ("windows_security","network_logon_success","MALICIOUS","T1021","lateral_movement"),
        ("windows_security","explicit_credentials_logon","SUSPICIOUS","T1078","lateral_movement"),
        ("network_flow","smb_connection","MALICIOUS","T1021.002","lateral_movement"),
        ("windows_sysmon","process_create","MALICIOUS","T1569","execution"),
        ("process_activity","remote_service_client","SUSPICIOUS","T1021","lateral_movement"),
        ("linux_auth","ssh_success","SUSPICIOUS","T1021.004","lateral_movement"),
        ("systemd_journal","remote_session_open","SUSPICIOUS","T1021","lateral_movement"),
    ],
    "possible_exfiltration": [
        ("filesystem","sensitive_file_read","SUSPICIOUS","T1005","collection"),
        ("process_activity","archive_utility_start","SUSPICIOUS","T1560","collection"),
        ("network_flow","large_outbound_transfer","MALICIOUS","T1041","exfiltration"),
        ("dns","external_transfer_lookup","SUSPICIOUS","T1048","exfiltration"),
        ("windows_sysmon","network_connection","SUSPICIOUS","T1041","exfiltration"),
        ("web_application","large_response_served","BENIGN","","exfiltration"),
    ],
    "web_attack_pattern": [
        ("web_application","request_validation_block","SUSPICIOUS","T1190","initial_access"),
        ("web_application","authentication_failure_burst","SUSPICIOUS","T1110","credential_access"),
        ("web_application","application_error","BENIGN","","initial_access"),
        ("network_flow","web_server_connection","BENIGN","","initial_access"),
        ("filesystem","web_root_file_access","SUSPICIOUS","T1005","collection"),
        ("process_activity","web_worker_child_process","MALICIOUS","T1059","execution"),
    ],
}

EVENTS = {
    "linux_auth": ["ssh_success","ssh_failed","sudo_elevation","invalid_user","pam_session_open","account_locked"],
    "systemd_journal": ["service_started","service_stopped","kernel_notice","daemon_warning","application_warning","sshd_auth_notice"],
    "windows_security": ["logon_success","logon_failure","network_logon_success","special_privileges_assigned","account_change","explicit_credentials_logon"],
    "windows_sysmon": ["process_create","network_connection","image_load","file_create","registry_value_set","dns_query"],
    "process_activity": ["process_start","process_exit","child_process_start","script_interpreter_start"],
    "network_flow": ["connection_allowed","connection_denied","web_server_connection","dns_transport","smb_connection"],
    "dns": ["dns_query","dns_response","nxdomain_response","internal_service_lookup"],
    "filesystem": ["file_created","file_modified","file_read","file_deleted","file_renamed"],
    "service_persistence": ["service_started","service_stopped","service_config_change","scheduled_task_create","startup_entry_change"],
    "web_application": ["http_request","http_auth_failure","http_response_error","request_validation_block","application_error"],
}


def pick_ip(rng, external=False):
    return rng.choice(DOC_IPS if external else PRIVATE_IPS)

def iso_time(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def random_time(rng):
    seconds = rng.randint(0, int((END-START).total_seconds()))
    return START + timedelta(seconds=seconds, microseconds=rng.randint(0,999999))

def base_row(record_id, source, rng, *, scenario_id="", correlation_id="", timestamp=None, host=None, user=None, src_ip=None, dst_ip=None, event_type=None, label="BENIGN", technique="", phase=""):
    if host is None:
        if source["id"] in {"linux_auth", "systemd_journal", "web_application"}:
            host = rng.choice([h for h in HOSTS if h.startswith("LINUX-")])
        elif source["id"] in {"windows_security", "windows_sysmon"}:
            host = rng.choice([h for h in HOSTS if h.startswith("WIN-")])
        else:
            host = rng.choice(HOSTS)
    host_os = "windows" if host.startswith("WIN") else "linux"
    timestamp = timestamp or random_time(rng)
    et = event_type or rng.choice(EVENTS[source["id"]])
    row = {k:"" for k in FIELDS}
    row.update({
        "record_id":record_id, "scenario_id":scenario_id, "correlation_id":correlation_id,
        "event_timestamp":iso_time(timestamp), "source_type":source["source_type"],
        "host":host, "host_os":host_os, "channel":"", "provider":"TRACEE-Synthetic",
        "event_code":"", "event_type":et, "severity":rng.choices(["INFO","LOW","MEDIUM","HIGH","CRITICAL"],[58,18,14,8,2])[0],
        "outcome":"success", "user":user or rng.choice(USERS), "source_ip":src_ip or pick_ip(rng),
        "destination_ip":dst_ip or pick_ip(rng), "source_port":str(rng.randint(1024,65535)),
        "destination_port":"", "protocol":"", "process_name":rng.choice(PROCESSES),
        "parent_process":rng.choice(PROCESSES), "command_line":"", "file_path":"", "file_operation":"",
        "domain":"", "dns_query_type":"", "service_name":"", "service_action":"",
        "http_method":"", "url_path":"", "http_status":"", "bytes_sent":"", "bytes_received":"",
        "auth_method":"", "log_level":"INFO", "message":"", "synthetic":"true", "sequence_no":str(rng.randint(1,9999999)),
    })
    row["scenario_id"] = scenario_id
    row["correlation_id"] = correlation_id
    row["severity"] = "HIGH" if label == "MALICIOUS" else ("MEDIUM" if label == "SUSPICIOUS" else row["severity"])
    row["outcome"] = "failure" if any(x in et for x in ("failed","failure","denied","nxdomain","blocked")) else "success"
    # Source-specific realistic metadata, all values remain synthetic.
    if source["id"] == "linux_auth":
        row.update(channel="authpriv", provider="sshd/pam/sudo", auth_method=rng.choice(["password","publickey","keyboard-interactive"]), log_level="WARNING" if row["outcome"]=="failure" else "INFO")
        row["message"] = f"{et.replace('_',' ')} for {row['user']} from {row['source_ip']}"
        row["event_code"] = "AUTH-" + str(rng.randint(1000,9999))
    elif source["id"] == "systemd_journal":
        row.update(channel="journal", provider=rng.choice(["systemd","sshd","kernel","sudo","nginx"]), log_level=rng.choice(["INFO","NOTICE","WARNING"]), service_name=rng.choice(["sshd.service","nginx.service","cron.service","systemd-logind.service"]))
        row["message"] = f"{et.replace('_',' ')} on {host}; unit={row['service_name']}"
        row["event_code"] = str(rng.randint(1,7))
    elif source["id"] == "windows_security":
        codes = {"logon_success":4624,"logon_failure":4625,"network_logon_success":4624,"special_privileges_assigned":4672,"account_change":4720,"explicit_credentials_logon":4648}
        row.update(channel="Security", provider="Microsoft-Windows-Security-Auditing", event_code=str(codes.get(et,4624)), auth_method=rng.choice(["Kerberos","NTLM","Negotiate"]))
        row["message"] = f"Windows Security {et.replace('_',' ')} for {row['user']}"
    elif source["id"] == "windows_sysmon":
        codes = {"process_create":1,"network_connection":3,"image_load":7,"file_create":11,"registry_value_set":13,"dns_query":22}
        row.update(channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon", event_code=str(codes.get(et,1)))
        row["process_name"] = rng.choice(["powershell.exe","cmd.exe","svchost.exe","services.exe","python.exe"])
        row["parent_process"] = rng.choice(["explorer.exe","services.exe","svchost.exe","w3wp.exe"])
        row["command_line"] = f'"{row["process_name"]}" --telemetry-simulation --record {record_id}'
        row["message"] = f"Sysmon event {codes.get(et,1)}: {et.replace('_',' ')}"
    elif source["id"] == "process_activity":
        row["command_line"] = f'{row["process_name"]} --synthetic-observation {record_id}'
        row["message"] = f"Process observation: {et.replace('_',' ')}"
    elif source["id"] == "network_flow":
        row.update(protocol=rng.choice(["TCP","UDP"]), destination_port=str(rng.choice([53,80,443,445,22,3389,8080])), bytes_sent=str(rng.randint(100,250000)), bytes_received=str(rng.randint(100,120000)))
        row["message"] = f"{et.replace('_',' ')} {row['source_ip']}:{row['source_port']} -> {row['destination_ip']}:{row['destination_port']}"
    elif source["id"] == "dns":
        row.update(domain=rng.choice(DOMAINS), dns_query_type=rng.choice(["A","AAAA","TXT","MX","PTR"]), destination_port="53", protocol="UDP")
        row["message"] = f"DNS {row['dns_query_type']} query for {row['domain']}"
    elif source["id"] == "filesystem":
        row.update(file_path=rng.choice(["/var/log/auth.log","/etc/ssh/sshd_config","/var/www/html/index.html","C:\\ProgramData\\TRACEE\\sample.dat","C:\\Windows\\Temp\\telemetry.tmp"]), file_operation=rng.choice(["read","write","create","rename","delete"]))
        row["message"] = f"File {row['file_operation']} observed at {row['file_path']}"
    elif source["id"] == "service_persistence":
        row.update(service_name=rng.choice(["TRACEE-Lab-Agent","UpdaterDemo","nginx.service","scheduled-maintenance"]), service_action=rng.choice(["start","stop","install","config_change","task_create"]))
        row["message"] = f"Service/persistence event: {et.replace('_',' ')}"
    elif source["id"] == "web_application":
        row.update(http_method=rng.choice(["GET","POST","PUT"]), url_path=rng.choice(["/login","/api/session","/health","/reports/export","/search"]), http_status=str(rng.choice([200,200,200,302,400,401,403,404,500])), bytes_sent=str(rng.randint(150,6000)), bytes_received=str(rng.randint(0,12000)), channel="access", provider="TRACEE-Web-Synthetic")
        row["message"] = f"{row['http_method']} {row['url_path']} status={row['http_status']}"
    return row


def scenario_blueprints(rng, n=1500):
    rows_by_source = {s["id"]: [] for s in SOURCES}
    truths = []
    event_number = 0
    profile_names = list(PROFILES)
    for idx in range(1, n+1):
        profile_name = profile_names[(idx-1) % len(profile_names)]
        profile = PROFILES[profile_name]
        scenario_id = f"SCN-{idx:05d}"
        correlation_id = f"COR-{idx:05d}"
        # Keep a consistent identity and host across correlated sources.
        scenario_windows_host = rng.choice([h for h in HOSTS if h.startswith("WIN-")])
        scenario_linux_host = rng.choice([h for h in HOSTS if h.startswith("LINUX-")])
        scenario_mixed_host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        src_ip = pick_ip(rng, external=True)
        dst_ip = pick_ip(rng, external=False)
        base = random_time(rng)
        for step, (source_id, event_type, label, technique, phase) in enumerate(profile, start=1):
            source = next(s for s in SOURCES if s["id"] == source_id)
            event_number += 1
            rid = f"TRC-DATA-{event_number:09d}"
            if source_id in {"linux_auth", "systemd_journal", "web_application"}:
                event_host = scenario_linux_host
            elif source_id in {"windows_security", "windows_sysmon"}:
                event_host = scenario_windows_host
            else:
                event_host = scenario_mixed_host
            row = base_row(rid, source, rng, scenario_id=scenario_id, correlation_id=correlation_id,
                           timestamp=base+timedelta(seconds=step*7+rng.randint(0,4)), host=event_host, user=user,
                           src_ip=src_ip, dst_ip=dst_ip, event_type=event_type, label=label,
                           technique=technique, phase=phase)
            if source_id == "network_flow" and "transfer" in event_type:
                row["bytes_sent"] = str(rng.randint(5_000_000, 80_000_000))
            if source_id == "dns" and event_type in {"high_entropy_subdomain","repeated_nxdomain"}:
                row["domain"] = f"{''.join(rng.choices(string.ascii_lowercase+string.digits,k=28))}.example"
            rows_by_source[source_id].append(row)
            if label != "BENIGN":
                truths.append({"record_id":rid,"scenario_id":scenario_id,"correlation_id":correlation_id,
                               "scenario_profile":profile_name,"label":label,"technique_id":technique,"tactic":phase,
                               "rationale":f"Synthetic {profile_name} scenario step {step}; ground truth is evaluation-only."})
    return rows_by_source, truths, event_number


def benign_row(record_id, source, rng):
    return base_row(record_id, source, rng)


def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--seed", type=int, default=SEED_DEFAULT)
    ap.add_argument("--scenarios", type=int, default=1500)
    args=ap.parse_args()
    root=args.output.resolve(); (root/"data").mkdir(parents=True,exist_ok=True); (root/"ground_truth").mkdir(parents=True,exist_ok=True)
    rng=random.Random(args.seed)
    scenario_rows, truths, next_id = scenario_blueprints(rng,args.scenarios)
    source_manifest=[]; overall=0
    for source in SOURCES:
        source_rng=random.Random(args.seed ^ (sum(ord(c) for c in source["id"])*7919))
        rows=scenario_rows[source["id"]]
        if len(rows)>source["count"]:
            raise SystemExit(f"scenario rows exceed allocation for {source['id']}")
        needed=source["count"]-len(rows)
        for _ in range(needed):
            next_id+=1
            rows.append(benign_row(f"TRC-DATA-{next_id:09d}",source,source_rng))
        source_rng.shuffle(rows)
        out=root/"data"/source["file"]
        with out.open("w",encoding="utf-8",newline="") as f:
            writer=csv.DictWriter(f,fieldnames=FIELDS,extrasaction="ignore",quoting=csv.QUOTE_MINIMAL)
            writer.writeheader(); writer.writerows(rows)
        digest=sha256(out); size=out.stat().st_size
        source_manifest.append({**source,"record_count":len(rows),"size_bytes":size,"sha256":digest,
                                "csv_path":f"data/{source['file']}","ground_truth_labels_in_source":False})
        overall+=len(rows)
        print(f"Generated {source['id']}: {len(rows):,} rows ({size/1024/1024:.1f} MiB)",flush=True)
    truth_path=root/"ground_truth"/"ground_truth_positive_only.csv"
    with truth_path.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["record_id","scenario_id","correlation_id","scenario_profile","label","technique_id","tactic","rationale"])
        w.writeheader(); w.writerows(truths)
    profile_descriptions={
        "credential_abuse":"Repeated authentication failures followed by successful access and follow-on activity.",
        "privilege_escalation":"Privilege elevation and protected-resource/service activity across host logs.",
        "suspicious_execution":"Unusual process ancestry, interpreter activity, and related file/network observations.",
        "dns_anomaly":"High-entropy or repeated DNS lookups associated with periodic outbound connections.",
        "persistence_change":"Service, scheduled-task, registry and startup configuration changes.",
        "lateral_movement":"Remote logons and service/network activity across related endpoints.",
        "possible_exfiltration":"Sensitive file reads, archive activity, and unusually large outbound transfers.",
        "web_attack_pattern":"Suspicious web requests, validation blocks, application outcomes and related host activity.",
    }
    profile_catalog=[]
    for profile_name, profile in PROFILES.items():
        profile_catalog.append({"profile_id":profile_name,"description":profile_descriptions[profile_name],
                                "source_ids":sorted({item[0] for item in profile}),
                                "steps":len(profile),"ground_truth_labels":["SUSPICIOUS","MALICIOUS"]})
    profile_path=root/"scenario_profiles.json"
    profile_path.write_text(json.dumps({"schema_version":"1.0","profiles":profile_catalog},indent=2),encoding="utf-8")
    # Manifest hash is excluded from its own digest; file checksums make the bundle verifiable.
    manifest={
        "dataset_name":"TRACEE Synthetic Multi-Source Security Telemetry Corpus",
        "dataset_version":VERSION,"generated_at":"2026-10-30T00:00:00Z","generator_seed":args.seed,
        "provenance":"100% synthetic records generated for TRACEE development, replay and parser testing. Not collected from real systems.",
        "total_records":overall,"record_count_range":"500000-1000000","scenario_count":args.scenarios,
        "positive_ground_truth_rows":len(truths),
        "ground_truth_policy":"Ground truth is stored separately. Rows absent from ground_truth_positive_only.csv are BENIGN by generation policy; labels are not present in the evidence CSVs.",
        "time_range_utc":{"start":iso_time(START),"end":iso_time(END)},
        "common_schema_version":"1.0","common_fields":FIELDS,
        "sources":source_manifest,
        "parser_mapping":{"linux_auth":"linux_auth","systemd_journal":"systemd_journal","windows_security":"windows_event","windows_sysmon":"windows_event","all_other_sources":"json_event"},
        "limitations":[
            "Synthetic and not a substitute for original endpoint telemetry or forensic evidence.",
            "Windows event rows are replay-adapted into the TRACEE versioned Windows Event JSONL envelope; they are not native EVTX files.",
            "The corpus does not contain raw PCAP payloads; network_flow.csv is flow metadata only.",
            "The CSV adapter creates parser-compatible replay batches; project API/UI wiring is a separate integration step documented in README.md."
        ],
        "ground_truth_file":{"path":"ground_truth/ground_truth_positive_only.csv","record_count":len(truths),"sha256":sha256(truth_path),"size_bytes":truth_path.stat().st_size},
        "scenario_profiles_file":{"path":"scenario_profiles.json","profile_count":len(profile_catalog),"sha256":sha256(profile_path),"size_bytes":profile_path.stat().st_size}
    }
    (root/"dataset_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    schema={"schema_version":"1.0","format":"CSV UTF-8","primary_key":"record_id","fields":{name:{"type":"string","nullable":True} for name in FIELDS},"notes":["All values are synthetic.","event_timestamp is UTC ISO-8601 with Z.","event_code is source-native numeric/text identifier, not record_id.","ground truth is intentionally external to evidence CSVs."]}
    (root/"schemas"/"common_record_schema.json").write_text(json.dumps(schema,indent=2),encoding="utf-8")
    print(f"TOTAL: {overall:,} records; positive labels: {len(truths):,}")

if __name__=="__main__": main()
