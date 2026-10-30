from __future__ import annotations

import json
import os
import random
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = Path(
    os.environ.get(
        "TRACEE_EVIDENCE_INPUT_DIR",
        BASE_DIR / "evidence",
    )
).resolve()

AUTH_OUTPUT = EVIDENCE_DIR / "tracee_generated_auth.log"
EVENT_OUTPUT = EVIDENCE_DIR / "tracee_generated_events.jsonl"

ATTACK_TYPES = [
    "BRUTE_FORCE",
    "ACCOUNT_COMPROMISE",
    "SUSPICIOUS_PROCESS_EXECUTION",
    "MALWARE_EXECUTION_SIMULATION",
    "COMMAND_EXECUTION",
    "DATA_EXFILTRATION_SIMULATION",
    "SUSPICIOUS_NETWORK_CONNECTION",
    "PRIVILEGE_ESCALATION_SIMULATION",
    "FILE_MODIFICATION",
    "MULTI_STAGE_INTRUSION",
]

USERS = [
    "admin",
    "analyst",
    "svc_backup",
    "svc_deploy",
    "operator",
    "developer",
]

PROCESSES = [
    "sshd",
    "bash",
    "python3",
    "curl",
    "powershell.exe",
    "rundll32.exe",
    "svchost.exe",
    "updater-helper",
    "backup-agent",
]

FILES = [
    "/srv/data/financial_report.xlsx",
    "/srv/data/customer_records.csv",
    "/var/tmp/update_package.bin",
    "/home/admin/.ssh/authorized_keys",
    "/opt/application/config.db",
    "/srv/shared/project_archive.zip",
]

DOMAINS = [
    "updates.example.test",
    "cdn.example.test",
    "storage.example.test",
    "telemetry.example.test",
]

COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "cat /etc/passwd",
    "ps aux",
    "find /srv/data -type f",
]

AUTH_EVENTS = {
    "FAILED_LOGIN",
    "SUCCESS_LOGIN",
}


def seeded_random() -> random.Random:
    return random.Random(
        secrets.randbits(64)
    )


RNG = seeded_random()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def random_private_ip() -> str:
    return (
        f"192.168."
        f"{RNG.randint(1, 254)}."
        f"{RNG.randint(2, 254)}"
    )


def random_destination_ip() -> str:
    return (
        f"10."
        f"{RNG.randint(10, 240)}."
        f"{RNG.randint(1, 254)}."
        f"{RNG.randint(2, 254)}"
    )


def choose_user() -> str:
    return RNG.choice(USERS)


def choose_process() -> str:
    return RNG.choice(PROCESSES)


def choose_file() -> str:
    return RNG.choice(FILES)


def choose_domain() -> str:
    return RNG.choice(DOMAINS)


def choose_command() -> str:
    return RNG.choice(COMMANDS)


def make_event(
    timestamp: datetime,
    event_type: str,
    attributes: dict[str, Any],
) -> dict[str, Any]:

    return {
        "timestamp": format_timestamp(timestamp),
        "event_type": event_type,
        "attributes": attributes,
    }


def login_event(
    timestamp: datetime,
    event_type: str,
    user: str,
    source_ip: str,
) -> dict[str, Any]:

    return make_event(
        timestamp,
        event_type,
        {
            "user": user,
            "ip": source_ip,
        },
    )


def process_event(
    timestamp: datetime,
    user: str,
    source_ip: str,
    process: str,
) -> dict[str, Any]:

    return make_event(
        timestamp,
        "PROCESS_START",
        {
            "user": user,
            "ip": source_ip,
            "process": process,
        },
    )


def generate_brute_force(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    events: list[dict[str, Any]] = []

    failures = RNG.randint(2, 5)

    current = start

    for _ in range(failures):
        events.append(
            login_event(
                current,
                "FAILED_LOGIN",
                user,
                source_ip,
            )
        )

        current += timedelta(
            seconds=RNG.randint(8, 35)
        )

    events.append(
        login_event(
            current,
            "SUCCESS_LOGIN",
            user,
            source_ip,
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        process_event(
            current,
            user,
            source_ip,
            "sshd",
        )
    )

    return events


def generate_account_compromise(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    process = choose_process()
    target_file = choose_file()

    events = [
        login_event(
            current,
            "FAILED_LOGIN",
            user,
            source_ip,
        )
    ]

    current += timedelta(
        seconds=RNG.randint(10, 40)
    )

    events.append(
        login_event(
            current,
            "SUCCESS_LOGIN",
            user,
            source_ip,
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 25)
    )

    events.append(
        process_event(
            current,
            user,
            source_ip,
            process,
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "FILE_ACCESS",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "file": target_file,
            },
        )
    )

    return events


def generate_suspicious_process(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start

    process = RNG.choice(
        [
            "powershell.exe",
            "rundll32.exe",
            "updater-helper",
            "python3",
            "backup-agent",
        ]
    )

    events = [
        make_event(
            current,
            "PROCESS_START",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
            },
        )
    ]

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "PROCESS_START",
            {
                "user": user,
                "ip": source_ip,
                "process": choose_process(),
                "parent_process": process,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": random_destination_ip(),
            },
        )
    )

    return events


def generate_malware_simulation(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    payload = "/var/tmp/update_package.bin"
    process = "updater-helper"
    destination_ip = random_destination_ip()

    events = [
        make_event(
            current,
            "FILE_CREATE",
            {
                "user": user,
                "ip": source_ip,
                "file": payload,
            },
        )
    ]

    current += timedelta(
        seconds=RNG.randint(8, 25)
    )

    events.append(
        make_event(
            current,
            "PROCESS_START",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "file": payload,
                "simulation": True,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "MALWARE_EXECUTION_SIMULATION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "file": payload,
                "simulation": True,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
            },
        )
    )

    return events


def generate_command_execution(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start

    events = [
        login_event(
            current,
            "SUCCESS_LOGIN",
            user,
            source_ip,
        )
    ]

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        process_event(
            current,
            user,
            source_ip,
            "bash",
        )
    )

    for _ in range(
        RNG.randint(2, 4)
    ):
        current += timedelta(
            seconds=RNG.randint(3, 15)
        )

        events.append(
            make_event(
                current,
                "COMMAND_EXECUTION",
                {
                    "user": user,
                    "ip": source_ip,
                    "process": "bash",
                    "command": choose_command(),
                },
            )
        )

    return events


def generate_data_exfiltration(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    process = RNG.choice(
        ["curl", "python3", "backup-agent"]
    )

    destination_ip = random_destination_ip()

    events: list[dict[str, Any]] = []

    files_to_access = RNG.randint(2, 5)

    for _ in range(files_to_access):

        file_path = choose_file()

        events.append(
            make_event(
                current,
                "FILE_ACCESS",
                {
                    "user": user,
                    "ip": source_ip,
                    "process": process,
                    "file": file_path,
                },
            )
        )

        current += timedelta(
            seconds=RNG.randint(4, 18)
        )

    events.append(
        make_event(
            current,
            "FILE_STAGING",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "file": "/tmp/archive_for_transfer.zip",
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 20)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "DATA_TRANSFER",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
                "bytes_transferred": RNG.randint(
                    250000,
                    8500000,
                ),
                "simulation": True,
            },
        )
    )

    return events


def generate_suspicious_network(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    process = choose_process()
    destination_ip = random_destination_ip()
    domain = choose_domain()

    events = [
        make_event(
            current,
            "PROCESS_START",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
            },
        )
    ]

    current += timedelta(
        seconds=RNG.randint(4, 15)
    )

    events.append(
        make_event(
            current,
            "DNS_QUERY",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "domain": domain,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(4, 15)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(4, 15)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "destination_ip": random_destination_ip(),
            },
        )
    )

    return events


def generate_privilege_escalation(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start

    events = [
        login_event(
            current,
            "SUCCESS_LOGIN",
            user,
            source_ip,
        )
    ]

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "PRIVILEGE_ESCALATION",
            {
                "user": user,
                "ip": source_ip,
                "method": "sudo",
                "target": "root",
                "simulation": True,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "PROCESS_START",
            {
                "user": "root",
                "ip": source_ip,
                "process": "bash",
                "parent_process": "sudo",
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "FILE_MODIFICATION",
            {
                "user": "root",
                "ip": source_ip,
                "file": "/etc/ssh/sshd_config",
            },
        )
    )

    return events


def generate_file_modification(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    process = choose_process()
    file_path = choose_file()

    events = [
        make_event(
            current,
            "FILE_ACCESS",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "file": file_path,
            },
        )
    ]

    for _ in range(
        RNG.randint(2, 4)
    ):

        current += timedelta(
            seconds=RNG.randint(5, 20)
        )

        events.append(
            make_event(
                current,
                "FILE_MODIFICATION",
                {
                    "user": user,
                    "ip": source_ip,
                    "process": process,
                    "file": file_path,
                },
            )
        )

    return events


def generate_multi_stage(
    start: datetime,
    user: str,
    source_ip: str,
) -> list[dict[str, Any]]:

    current = start
    process = "bash"
    target_file = choose_file()
    destination_ip = random_destination_ip()

    events: list[dict[str, Any]] = []

    for _ in range(2):

        events.append(
            login_event(
                current,
                "FAILED_LOGIN",
                user,
                source_ip,
            )
        )

        current += timedelta(
            seconds=RNG.randint(8, 20)
        )

    events.append(
        login_event(
            current,
            "SUCCESS_LOGIN",
            user,
            source_ip,
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        process_event(
            current,
            user,
            source_ip,
            process,
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "COMMAND_EXECUTION",
            {
                "user": user,
                "ip": source_ip,
                "process": process,
                "command": choose_command(),
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "PRIVILEGE_ESCALATION",
            {
                "user": user,
                "ip": source_ip,
                "method": "sudo",
                "target": "root",
                "simulation": True,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "FILE_ACCESS",
            {
                "user": "root",
                "ip": source_ip,
                "process": process,
                "file": target_file,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "NETWORK_CONNECTION",
            {
                "user": "root",
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
            },
        )
    )

    current += timedelta(
        seconds=RNG.randint(5, 15)
    )

    events.append(
        make_event(
            current,
            "DATA_TRANSFER",
            {
                "user": "root",
                "ip": source_ip,
                "process": process,
                "destination_ip": destination_ip,
                "bytes_transferred": RNG.randint(
                    500000,
                    12000000,
                ),
                "simulation": True,
            },
        )
    )

    return events


GENERATORS = {
    "BRUTE_FORCE": generate_brute_force,
    "ACCOUNT_COMPROMISE": generate_account_compromise,
    "SUSPICIOUS_PROCESS_EXECUTION": generate_suspicious_process,
    "MALWARE_EXECUTION_SIMULATION": generate_malware_simulation,
    "COMMAND_EXECUTION": generate_command_execution,
    "DATA_EXFILTRATION_SIMULATION": generate_data_exfiltration,
    "SUSPICIOUS_NETWORK_CONNECTION": generate_suspicious_network,
    "PRIVILEGE_ESCALATION_SIMULATION": generate_privilege_escalation,
    "FILE_MODIFICATION": generate_file_modification,
    "MULTI_STAGE_INTRUSION": generate_multi_stage,
}


def cleanup_previous_generation() -> None:

    for output_file in (
        AUTH_OUTPUT,
        EVENT_OUTPUT,
    ):

        if output_file.exists():
            output_file.unlink()


def generate_incident() -> dict[str, Any]:

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    cleanup_previous_generation()

    run_id = os.environ.get(
        "TRACEE_RUN_ID",
        "UNASSIGNED",
    )

    scenario_count = RNG.randint(1, 3)

    selected_types = RNG.sample(
        ATTACK_TYPES,
        scenario_count,
    )

    base_time = (
        utc_now()
        - timedelta(
            minutes=RNG.randint(2, 12)
        )
    )

    shared_user = choose_user()
    shared_source_ip = random_private_ip()

    auth_events: list[dict[str, Any]] = []
    application_events: list[dict[str, Any]] = []

    total_events = 0
    scenario_records: list[dict[str, Any]] = []

    current_start = base_time

    for index, attack_type in enumerate(
        selected_types,
        start=1,
    ):

        generator = GENERATORS[
            attack_type
        ]

        scenario_id = (
            f"SIM-{index:03d}"
        )

        generated_events = generator(
            current_start,
            shared_user,
            shared_source_ip,
        )

        for event in generated_events:

            attributes = event[
                "attributes"
            ]

            attributes[
                "run_id"
            ] = run_id

            attributes[
                "scenario_id"
            ] = scenario_id

            attributes[
                "scenario_type"
            ] = attack_type

            if (
                event["event_type"]
                in AUTH_EVENTS
            ):
                auth_events.append(
                    event
                )
            else:
                application_events.append(
                    event
                )

        total_events += len(
            generated_events
        )

        scenario_records.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": attack_type,
                "event_count": len(
                    generated_events
                ),
            }
        )

        current_start += timedelta(
            seconds=RNG.randint(
                20,
                60,
            )
        )

    scenario_metadata_event = make_event(
        base_time,
        "SCENARIO_METADATA",
        {
            "run_id": run_id,
            "scenario_count": scenario_count,
            "scenarios": selected_types,
            "event_count": total_events,
            "simulation": True,
        },
    )

    application_events.insert(
        0,
        scenario_metadata_event,
    )

    with open(
        AUTH_OUTPUT,
        "w",
        encoding="utf-8",
    ) as file:

        for event in sorted(
            auth_events,
            key=lambda item: item[
                "timestamp"
            ],
        ):

            attrs = event[
                "attributes"
            ]

            file.write(
                f'{event["timestamp"]} '
                f'{event["event_type"]} '
                f'user={attrs["user"]} '
                f'ip={attrs["ip"]}\n'
            )

    with open(
        EVENT_OUTPUT,
        "w",
        encoding="utf-8",
    ) as file:

        for event in sorted(
            application_events,
            key=lambda item: item[
                "timestamp"
            ],
        ):

            file.write(
                json.dumps(
                    event,
                    separators=(
                        ",",
                        ":",
                    ),
                )
                + "\n"
            )

    return {
        "run_id": run_id,
        "scenario_count": scenario_count,
        "scenarios": scenario_records,
        "event_count": total_events,
        "auth_events": len(
            auth_events
        ),
        "application_events": len(
            application_events
        ),
        "auth_file": AUTH_OUTPUT.name,
        "event_file": EVENT_OUTPUT.name,
    }


def main() -> int:

    result = generate_incident()

    print(
        "[INFO] Synthetic incident generated"
    )

    print(
        f'[INFO] Attack scenarios: '
        f'{result["scenario_count"]}'
    )

    for scenario in result[
        "scenarios"
    ]:

        print(
            f'[INFO] '
            f'{scenario["scenario_id"]}: '
            f'{scenario["scenario_type"]} '
            f'events={scenario["event_count"]}'
        )

    print(
        f'[INFO] Total synthetic events: '
        f'{result["event_count"]}'
    )

    print(
        f'[INFO] Authentication evidence: '
        f'{result["auth_file"]}'
    )

    print(
        f'[INFO] Application evidence: '
        f'{result["event_file"]}'
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
