# Data Dictionary

Every source CSV uses the same 38-column schema. Blank values mean that a field is not applicable or was not generated for that source. All values are synthetic.

| Field | Meaning |
|---|---|
| `record_id` | Globally unique synthetic row identifier (`TRC-DATA-...`). |
| `scenario_id` | Shared synthetic scenario identifier for correlated rows; blank for background rows. |
| `correlation_id` | Synthetic grouping identifier shared across events in a scenario. |
| `event_timestamp` | Original event time in UTC ISO-8601 format with `Z`. |
| `source_type` | Source family (for example `linux_auth`, `windows_event_log`, `network_flow`). |
| `host` | Synthetic endpoint hostname. |
| `host_os` | `windows` or `linux` for the generated host. |
| `channel` | Source channel/log stream, where applicable. |
| `provider` | Synthetic event provider/process family. |
| `event_code` | Source-native event ID/code when relevant; not the dataset record ID. |
| `event_type` | Normalized synthetic event name. |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `outcome` | Coarse operation outcome such as `success` or `failure`. |
| `user` | Synthetic account name. |
| `source_ip` | Synthetic source IP (private or RFC 5737 documentation range). |
| `destination_ip` | Synthetic destination IP. |
| `source_port` | Synthetic source port. |
| `destination_port` | Synthetic destination/service port. |
| `protocol` | Network protocol, typically TCP or UDP. |
| `process_name` | Descriptive process name; not executable content. |
| `parent_process` | Descriptive parent process. |
| `command_line` | Harmless synthetic telemetry string, not intended to be executed. |
| `file_path` | Synthetic file path. |
| `file_operation` | File operation such as read, write, create, rename or delete. |
| `domain` | Synthetic `.example` or `.test` domain. |
| `dns_query_type` | DNS record type such as A, AAAA, TXT, MX or PTR. |
| `service_name` | Synthetic service/task name. |
| `service_action` | Service or persistence operation. |
| `http_method` | Synthetic HTTP method. |
| `url_path` | Synthetic application path; no real host URL. |
| `http_status` | Synthetic HTTP status code. |
| `bytes_sent` | Synthetic byte count. |
| `bytes_received` | Synthetic byte count. |
| `auth_method` | Synthetic authentication mechanism. |
| `log_level` | Source log level. |
| `message` | Human-readable synthetic event summary. |
| `synthetic` | Always `true` for this corpus. |
| `sequence_no` | Synthetic sequence/record counter; source-specific ordering is not a forensic sequence. |

## Evaluation labels

`ground_truth/ground_truth_positive_only.csv` contains only positive rows. `scenario_profile` identifies one of the eight profiles in `scenario_profiles.json`; `label` is `SUSPICIOUS` or `MALICIOUS`; `technique_id` and `tactic` are scenario annotations. Rows not listed in that file are generated benign records. This file must remain outside the evidence and detection input path.
