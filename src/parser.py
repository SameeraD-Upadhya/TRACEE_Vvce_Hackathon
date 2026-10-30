import hashlib
import json

from config import (
    NORMALIZED_EVENTS_FILE,
    TRUSTED_EVIDENCE_FILE,
    VAULT_EVIDENCE_DIR,
)

from logging_utils import (
    error,
    info,
    warning,
)

from parsers.registry import get_parsers


def sha256_text(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def create_event_id(
    evidence_id,
    line_number,
    raw_line,
):
    material = (
        f"{evidence_id}|"
        f"{line_number}|"
        f"{raw_line}"
    )

    return (
        "TRACE-"
        + sha256_text(material)[:24]
    )


def read_sample_lines(
    file_path,
    limit=20,
):
    lines = []

    with open(
        file_path,
        "r",
        errors="replace",
    ) as file:

        for line in file:

            lines.append(
                line.rstrip("\n")
            )

            if len(lines) >= limit:
                break

    return lines


def select_parser(
    file_path,
    sample_lines,
):
    for parser in get_parsers():

        if parser.can_parse(
            file_path,
            sample_lines,
        ):
            return parser

    return None


def validate_parsed_event(event):
    required_fields = [
        "timestamp",
        "event_type",
        "attributes",
    ]

    for field in required_fields:

        if field not in event:
            return False

    if not isinstance(
        event["attributes"],
        dict,
    ):
        return False

    return True


def main():

    info("Evidence parsing started")

    if not TRUSTED_EVIDENCE_FILE.exists():

        error(
            "Trusted evidence record not found"
        )

        return 1

    with open(
        TRUSTED_EVIDENCE_FILE,
        "r",
    ) as file:

        trust_record = json.load(file)

    if trust_record.get("status") != "VERIFIED":

        error(
            "Evidence is not marked as trusted"
        )

        return 1

    NORMALIZED_EVENTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    total_events = 0
    blank_lines = 0
    unparsed_lines = 0
    parser_usage = {}

    with open(
        NORMALIZED_EVENTS_FILE,
        "w",
    ) as output:

        for evidence in trust_record["evidence"]:

            evidence_id = evidence[
                "evidence_id"
            ]

            evidence_file = (
                VAULT_EVIDENCE_DIR
                / f"{evidence_id}.log"
            )

            if not evidence_file.exists():

                error(
                    f"Trusted evidence missing: "
                    f"{evidence_id}"
                )

                return 1

            sample_lines = read_sample_lines(
                evidence_file
            )

            parser = select_parser(
                evidence_file,
                sample_lines,
            )

            if parser is None:

                error(
                    f"No parser available for "
                    f"evidence: {evidence_id}"
                )

                return 1

            parser_usage[parser.name] = (
                parser_usage.get(
                    parser.name,
                    0,
                ) + 1
            )

            info(
                f"Parser selected: "
                f"{parser.name} "
                f"({evidence_id})"
            )

            with open(
                evidence_file,
                "r",
                errors="replace",
            ) as file:

                for line_number, line in enumerate(
                    file,
                    start=1,
                ):

                    raw_line = line.rstrip("\n")

                    if not raw_line.strip():

                        blank_lines += 1
                        continue

                    parsed = parser.parse_line(
                        raw_line
                    )

                    if not parsed:

                        unparsed_lines += 1
                        continue

                    if not validate_parsed_event(
                        parsed
                    ):

                        error(
                            "Parser returned an invalid "
                            f"event at line {line_number}"
                        )

                        return 1

                    event = {
                        "schema_version": "1.1",
                        "event_id": create_event_id(
                            evidence_id,
                            line_number,
                            raw_line,
                        ),
                        "run_id": trust_record[
                            "run_id"
                        ],
                        "evidence_id": evidence_id,
                        "evidence_sha256":
                            evidence["sha256"],
                        "parser": parser.name,
                        "timestamp":
                            parsed["timestamp"],
                        "event_type":
                            parsed["event_type"],
                        "source":
                            evidence["source"],
                        "line_number": line_number,
                        "raw_line_sha256":
                            sha256_text(raw_line),
                        "attributes":
                            parsed["attributes"],
                    }

                    output.write(
                        json.dumps(event)
                        + "\n"
                    )

                    total_events += 1

    info(
        f"Events parsed: {total_events}"
    )

    info(
        f"Blank lines: {blank_lines}"
    )

    info(
        f"Unparsed lines: {unparsed_lines}"
    )

    if unparsed_lines:
        warning(
            "Some evidence lines were not "
            "recognized by the selected parser"
        )

    for parser_name, count in parser_usage.items():

        info(
            f"Parser usage: "
            f"{parser_name} = {count}"
        )

    info(
        f"Output: {NORMALIZED_EVENTS_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
