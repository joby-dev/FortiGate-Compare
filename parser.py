"""Parse firewall policies from a FortiGate CLI configuration export."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path


POLICY_FIELDS = (
    "name",
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "service",
    "schedule",
    "action",
    "nat",
    "logtraffic",
    "comments",
    "status",
)
POLICY_SECTIONS = {
    "config firewall policy": "Firewall",
    "config firewall proxy-policy": "Proxy",
    "config firewall local-in-policy": "Local-In",
    "config firewall policy6": "IPv6 Firewall",
    "config firewall proxy-policy6": "IPv6 Proxy",
}
MULTI_VALUE_FIELDS = {"srcintf", "dstintf", "srcaddr", "dstaddr", "service"}
logger = logging.getLogger(__name__)


class ConfigParseError(ValueError):
    """Raised when a configuration cannot be parsed as a policy export."""


@dataclass
class ParseResult:
    """Policies and recoverable issues found while parsing one configuration."""

    policies: dict[tuple[str, str], dict[str, object]]
    warning_logs: list[dict[str, object]] = field(default_factory=list)
    lines_processed: int = 0

    @property
    def warnings(self) -> list[dict[str, object]]:
        return [item for item in self.warning_logs if item["severity"] == "Warning"]

    @property
    def errors(self) -> list[dict[str, object]]:
        return [item for item in self.warning_logs if item["severity"] == "Error"]

    @property
    def policies_parsed_successfully(self) -> int:
        return sum(
            policy.get("parse_status") == "Parsed Successfully"
            for policy in self.policies.values()
        )

    @property
    def policies_partially_parsed(self) -> int:
        return sum(
            policy.get("parse_status") == "Partial Parse"
            for policy in self.policies.values()
        )


def _tokenize_line(line: str) -> tuple[list[str], bool]:
    """Split a FortiGate command line while recovering unmatched quotes."""
    tokens: list[str] = []
    token: list[str] = []
    in_quotes = False
    token_started = False
    index = 0

    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            next_char = line[index + 1]
            if next_char in {'"', "\\"}:
                token.append(next_char)
                token_started = True
                index += 2
                continue
            token.append(char)
            token_started = True
        elif char == '"':
            in_quotes = not in_quotes
            token_started = True
        elif char.isspace() and not in_quotes:
            if token_started:
                tokens.append("".join(token))
                token.clear()
                token_started = False
        else:
            token.append(char)
            token_started = True
        index += 1

    if token_started:
        tokens.append("".join(token))
    return tokens, in_quotes


def parse_firewall_config_safe(config_text: str) -> ParseResult:
    """Parse supported policies, recovering from malformed lines.

    Values supplied to ``set`` are represented as strings when there is one
    token. Multi-value interface, address, and service fields are represented
    as lists. Incomplete quotes are closed logically at the end of their line,
    logged as warnings, and do not prevent subsequent policy lines parsing.
    """
    if not isinstance(config_text, str) or not config_text.strip():
        raise ConfigParseError("The uploaded file is empty or is not valid text.")

    policies: dict[tuple[str, str], dict[str, object]] = {}
    warning_logs: list[dict[str, object]] = []
    current_section: str | None = None
    current_policy: dict[str, object] | None = None
    found_section = False
    lines = config_text.splitlines()

    def record_issue(
        line_number: int,
        raw_line: str,
        message: str,
        severity: str,
    ) -> None:
        warning_logs.append(
            {
                "line": line_number,
                "content": raw_line,
                "error": message,
                "severity": severity,
            }
        )
        logger.warning(f"Line {line_number}: malformed configuration detected")
        if current_policy is not None:
            current_policy["_partial_parse"] = True

    def finish_policy() -> None:
        nonlocal current_policy
        if current_policy is None or current_section is None:
            return
        is_partial = bool(current_policy.pop("_partial_parse", False))
        current_policy["parse_status"] = (
            "Partial Parse" if is_partial else "Parsed Successfully"
        )
        policy_key = (current_section, str(current_policy["policyid"]))
        if policy_key in policies:
            record_issue(
                line_number,
                raw_line,
                f"Duplicate {current_section} policy ID {policy_key[1]}.",
                "Error",
            )
        else:
            policies[policy_key] = current_policy
        current_policy = None

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        normalized_line = line.lower()
        if current_section is None:
            current_section = POLICY_SECTIONS.get(normalized_line)
            if current_section is not None:
                found_section = True
            continue

        try:
            tokens, incomplete_quote = _tokenize_line(line)
            if not tokens:
                continue
            if incomplete_quote:
                record_issue(
                    line_number,
                    raw_line,
                    "Missing closing quote; value was recovered to the end of the line.",
                    "Warning",
                )

            command = tokens[0].lower()
            if command == "edit":
                if current_policy is not None:
                    record_issue(
                        line_number,
                        raw_line,
                        f"Policy {current_policy['policyid']} is missing its 'next' terminator.",
                        "Error",
                    )
                    finish_policy()
                if len(tokens) != 2:
                    raise ValueError("Expected 'edit <policyid>'.")
                current_policy = {
                    "policy_type": current_section,
                    "policyid": tokens[1],
                }
                continue

            if command == "set":
                if current_policy is None:
                    raise ValueError("Found 'set' outside a policy block.")
                if len(tokens) < 2:
                    raise ValueError("Missing setting name.")
                field_name = tokens[1].lower()
                if len(tokens) < 3:
                    raise ValueError(f"Missing value for setting '{field_name}'.")
                if field_name in POLICY_FIELDS:
                    values = tokens[2:]
                    if field_name in MULTI_VALUE_FIELDS and len(values) > 1:
                        current_policy[field_name] = values
                    else:
                        current_policy[field_name] = " ".join(values)
                continue

            if command == "next":
                if current_policy is None:
                    raise ValueError("Found 'next' outside a policy block.")
                for field_name in POLICY_FIELDS:
                    current_policy.setdefault(field_name, None)
                finish_policy()
                continue

            if command == "end":
                if current_policy is not None:
                    record_issue(
                        line_number,
                        raw_line,
                        f"Policy {current_policy['policyid']} is missing its 'next' terminator.",
                        "Error",
                    )
                    finish_policy()
                current_section = None
                continue

            if command == "config":
                raise ValueError("Unexpected nested configuration statement.")
        except Exception as error:
            record_issue(line_number, raw_line, str(error), "Error")
            continue

    if current_section is not None:
        if current_policy is not None:
            record_issue(
                len(lines),
                lines[-1],
                f"Policy {current_policy['policyid']} is missing its 'next' terminator.",
                "Error",
            )
            finish_policy()
        record_issue(
            len(lines),
            lines[-1],
            f"The {current_section} section is missing 'end'.",
            "Error",
        )
    if not found_section:
        section_list = ", ".join(POLICY_SECTIONS)
        raise ConfigParseError(
            f"No supported policy section was found. Expected one of: {section_list}."
        )

    return ParseResult(policies, warning_logs, len(lines))


def parse_firewall_config(config_text: str) -> dict[tuple[str, str], dict[str, object]]:
    """Compatibility wrapper returning only parsed policies."""
    return parse_firewall_config_safe(config_text).policies


def parse_firewall_policies(config_text: str) -> dict[str, dict[str, object]]:
    """Return only IPv4 firewall policies, keyed by policy ID."""
    policies = parse_firewall_config(config_text)
    firewall_policies = {
        policy_id: policy
        for (policy_type, policy_id), policy in policies.items()
        if policy_type == "Firewall"
    }
    if not firewall_policies:
        raise ConfigParseError('No "config firewall policy" section was found.')
    return firewall_policies


def parse_firewall_policy_file(file_path: str | Path) -> dict[str, dict[str, object]]:
    """Read and parse a UTF-8 FortiGate configuration file."""
    try:
        config_text = Path(file_path).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise ConfigParseError(f"Could not read the configuration file: {error}") from error
    return parse_firewall_policies(config_text)


def parse_firewall_config_file(
    file_path: str | Path,
) -> dict[tuple[str, str], dict[str, object]]:
    """Read and parse all supported policy sections from a config file."""
    try:
        config_text = Path(file_path).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise ConfigParseError(f"Could not read the configuration file: {error}") from error
    return parse_firewall_config(config_text)