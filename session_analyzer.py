"""Parse and summarize FortiGate diagnose sys session list output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO

import pandas as pd


_SESSION_START = re.compile(r"(?m)^session info:\s*")
_KEY_VALUE = re.compile(r"\b([\w-]+)=([^\s,]+)")
_ENDPOINT = re.compile(
    r"(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]):(?P<src_port>\d+)"
    r"->(?P<dst_ip>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]):(?P<dst_port>\d+)"
)
_STATISTICS = re.compile(
    r"statistic\s*\(bytes/packets/allow_err\):\s*"
    r"org=(\d+)/(\d+)(?:/\d+)?\s+reply=(\d+)/(\d+)(?:/\d+)?",
    re.IGNORECASE,
)
_SPEED = re.compile(
    r"\b(tx|rx)\s+speed\s*\(Bps/kbps\):\s*([\d.]+)/([\d.]+)",
    re.IGNORECASE,
)
_STATE = re.compile(r"\bstate=(.*?)(?=\s+[\w-]+=|$)", re.IGNORECASE)
_OFFLOAD = re.compile(r"\boffload=(\d+)\s*/\s*(\d+)", re.IGNORECASE)
_NO_OFFLOAD_REASON = re.compile(r"\bno_ofld_reason:\s*(.*)", re.IGNORECASE)

APPLICATIONS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    389: "LDAP",
    443: "HTTPS",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    3389: "RDP",
}

SESSION_COLUMNS = [
    "Protocol",
    "Proto State",
    "Duration",
    "Expire",
    "Timeout",
    "Policy ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "TX Speed",
    "RX Speed",
    "Origin Bytes",
    "Reply Bytes",
    "Origin Packets",
    "Reply Packets",
    "Session State",
    "Serial Number",
    "Offload Status",
    "no_ofld_reason",
    "Application",
    "Port",
    "Duration Human Format",
    "Total Bytes",
    "Total Traffic MB",
    "Total Traffic GB",
    "Current Throughput",
    "Current Throughput Mbps",
    "Upload Bytes",
    "Download Bytes",
    "Traffic",
]


@dataclass
class SessionAnalysis:
    sessions: pd.DataFrame
    summary: dict[str, object]
    top_talkers: pd.DataFrame
    longest_sessions: pd.DataFrame
    source_analysis: pd.DataFrame
    destination_analysis: pd.DataFrame
    health_findings: pd.DataFrame
    incident_summary: str


def _number(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _integer(value: object) -> int:
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    return int(_number(value))


def format_duration(seconds: int) -> str:
    hours, remainder = divmod(max(0, seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def format_traffic(megabytes: float) -> str:
    if megabytes >= 1024:
        return f"{megabytes / 1024:.3f} GB"
    return f"{megabytes:.2f} MB"


def _application(source_port: int, destination_port: int) -> tuple[str, int]:
    if destination_port in APPLICATIONS:
        return APPLICATIONS[destination_port], destination_port
    if source_port in APPLICATIONS:
        return APPLICATIONS[source_port], source_port
    return "Custom Port", destination_port or source_port


def _parse_block(block: str) -> dict[str, object]:
    values = {match.group(1).casefold(): match.group(2) for match in _KEY_VALUE.finditer(block)}
    endpoint = _ENDPOINT.search(block)
    statistics = _STATISTICS.search(block)
    speeds = {match.group(1).casefold(): match.group(3) for match in _SPEED.finditer(block)}
    state_match = _STATE.search(block)
    offload_match = _OFFLOAD.search(block)
    reason_match = _NO_OFFLOAD_REASON.search(block)

    source_port = _integer(endpoint.group("src_port")) if endpoint else 0
    destination_port = _integer(endpoint.group("dst_port")) if endpoint else 0
    application, port = _application(source_port, destination_port)
    origin_bytes = int(statistics.group(1)) if statistics else 0
    origin_packets = int(statistics.group(2)) if statistics else 0
    reply_bytes = int(statistics.group(3)) if statistics else 0
    reply_packets = int(statistics.group(4)) if statistics else 0
    reason = reason_match.group(1).strip() if reason_match else ""
    npu_state = _integer(values.get("npu_state", "0"))
    is_offloaded = (
        not reason
        and (
            (offload_match is not None and (int(offload_match.group(1)) > 0 or int(offload_match.group(2)) > 0))
            or npu_state > 0
        )
    )
    duration = _integer(values.get("duration", 0))
    tx_speed = _number(speeds.get("tx", 0))
    rx_speed = _number(speeds.get("rx", 0))
    total_bytes = origin_bytes + reply_bytes
    traffic_mb = total_bytes / (1024 * 1024)
    throughput_kbps = tx_speed + rx_speed
    session = {
        "Protocol": values.get("proto", ""),
        "Proto State": values.get("proto_state", ""),
        "Duration": duration,
        "Expire": _integer(values.get("expire", 0)),
        "Timeout": _integer(values.get("timeout", 0)),
        "Policy ID": values.get("policy_id", ""),
        "Source IP": endpoint.group("src_ip").strip("[]") if endpoint else "",
        "Source Port": source_port,
        "Destination IP": endpoint.group("dst_ip").strip("[]") if endpoint else "",
        "Destination Port": destination_port,
        "TX Speed": tx_speed,
        "RX Speed": rx_speed,
        "Origin Bytes": origin_bytes,
        "Reply Bytes": reply_bytes,
        "Origin Packets": origin_packets,
        "Reply Packets": reply_packets,
        "Session State": state_match.group(1).strip() if state_match else values.get("state", ""),
        "Serial Number": values.get("serial", ""),
        "Offload Status": "Offloaded" if is_offloaded else "Not Offloaded",
        "no_ofld_reason": reason,
        "Application": application,
        "Port": port,
        "Duration Human Format": format_duration(duration),
        "Total Bytes": total_bytes,
        "Total Traffic MB": traffic_mb,
        "Total Traffic GB": traffic_mb / 1024,
        "Current Throughput": throughput_kbps,
        "Current Throughput Mbps": throughput_kbps / 1024,
        "Upload Bytes": origin_bytes,
        "Download Bytes": reply_bytes,
        "Traffic": format_traffic(traffic_mb),
    }
    return session


def parse_sessions(text: str) -> pd.DataFrame:
    """Parse all `session info:` blocks with one pass over the pasted input."""
    if not isinstance(text, str) or not text.strip():
        return pd.DataFrame(columns=SESSION_COLUMNS)

    markers = list(_SESSION_START.finditer(text))
    records = [
        _parse_block(text[marker.start() : markers[index + 1].start() if index + 1 < len(markers) else len(text)])
        for index, marker in enumerate(markers)
    ]
    return pd.DataFrame.from_records(records, columns=SESSION_COLUMNS)


def _health_findings(sessions: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "Severity",
        "Finding",
        "Source IP",
        "Destination IP",
        "Session State",
        "Port",
        "Application",
        "Policy ID",
        "Duration",
        "Traffic",
        "Current Throughput Mbps",
        "Details",
    ]
    findings = []
    rules = (
        (sessions["Duration"] > 14400, "Medium", "LONG RUNNING", "Duration exceeds 4 hours."),
        (sessions["Total Traffic GB"] > 1, "High", "VERY HIGH BANDWIDTH", "Traffic exceeds 1 GB."),
        (sessions["Current Throughput Mbps"] > 100, "Medium", "HIGH THROUGHPUT", "Current throughput exceeds 100 Mbps."),
        (sessions["no_ofld_reason"].ne(""), "Informational", "NOT OFFLOADED", "FortiGate reported a no_ofld_reason."),
    )
    for condition, severity, finding, details in rules:
        for _, row in sessions.loc[condition].iterrows():
            findings.append(
                {
                    "Severity": severity,
                    "Finding": finding,
                    "Source IP": row["Source IP"],
                    "Destination IP": row["Destination IP"],
                    "Session State": row["Session State"],
                    "Port": row["Port"],
                    "Application": row["Application"],
                    "Policy ID": row["Policy ID"],
                    "Duration": row["Duration Human Format"],
                    "Traffic": row["Traffic"],
                    "Current Throughput Mbps": row["Current Throughput Mbps"],
                    "Details": details + (f" Reason: {row['no_ofld_reason']}" if finding == "NOT OFFLOADED" else ""),
                }
            )
    return pd.DataFrame(findings, columns=columns)


def analyze_sessions(text: str) -> SessionAnalysis:
    """Parse once, then derive incident summaries and sortable analysis tables."""
    sessions = parse_sessions(text)
    count = len(sessions)
    top_talkers = sessions.sort_values("Total Bytes", ascending=False).head(20).loc[
        :, ["Source IP", "Destination IP", "Port", "Application", "Duration Human Format", "Total Traffic GB", "Current Throughput Mbps"]
    ].rename(columns={"Duration Human Format": "Duration", "Total Traffic GB": "Traffic GB"}).reset_index(drop=True)
    longest_sessions = sessions.sort_values("Duration", ascending=False).head(20).loc[
        :, ["Source IP", "Destination IP", "Port", "Application", "Duration Human Format", "Duration", "Total Traffic GB", "Current Throughput Mbps"]
    ].rename(columns={"Duration Human Format": "Duration Format"}).reset_index(drop=True)
    source_analysis = (
        sessions.groupby("Source IP", dropna=False)
        .agg(
            **{
                "Session Count": ("Source IP", "size"),
                "Total Traffic GB": ("Total Traffic GB", "sum"),
                "Average Throughput Mbps": ("Current Throughput Mbps", "mean"),
            }
        )
        .sort_values("Total Traffic GB", ascending=False)
        .reset_index()
    )
    destination_analysis = (
        sessions.groupby("Destination IP", dropna=False)
        .agg(
            **{
                "Session Count": ("Destination IP", "size"),
                "Total Traffic GB": ("Total Traffic GB", "sum"),
            }
        )
        .sort_values("Total Traffic GB", ascending=False)
        .reset_index()
    )
    health_findings = _health_findings(sessions)
    total_traffic_gb = float(sessions["Total Traffic GB"].sum()) if count else 0.0
    average_throughput = float(sessions["Current Throughput Mbps"].mean()) if count else 0.0
    highest = sessions.sort_values("Current Throughput Mbps", ascending=False).iloc[0] if count else None
    longest = sessions.sort_values("Duration", ascending=False).iloc[0] if count else None
    top_source = source_analysis.iloc[0]["Source IP"] if not source_analysis.empty else "N/A"
    top_destination = destination_analysis.iloc[0]["Destination IP"] if not destination_analysis.empty else "N/A"
    http_count = int(sessions["Application"].eq("HTTP").sum())
    https_count = int(sessions["Application"].eq("HTTPS").sum())
    not_offloaded = int(sessions["Offload Status"].ne("Offloaded").sum())
    highest_label = (
        f"{highest['Source IP']} -> {highest['Destination IP']}:{highest['Port']} "
        f"({highest['Current Throughput Mbps']:.3f} Mbps)"
        if highest is not None
        else "N/A"
    )
    longest_label = (
        f"{longest['Source IP']} -> {longest['Destination IP']}:{longest['Port']} "
        f"({longest['Duration Human Format']})"
        if longest is not None
        else "N/A"
    )
    summary: dict[str, object] = {
        "Total Sessions": count,
        "Unique Sources": sessions["Source IP"].nunique() if count else 0,
        "Unique Destinations": sessions["Destination IP"].nunique() if count else 0,
        "Total Traffic GB": total_traffic_gb,
        "Average Throughput Mbps": average_throughput,
        "Highest Throughput Session": highest_label,
        "Longest Session": longest_label,
        "Sessions Without NPU Offload": not_offloaded,
        "HTTP Sessions": http_count,
        "HTTPS Sessions": https_count,
        "Top Source IP": top_source,
        "Top Destination IP": top_destination,
    }
    if health_findings.empty:
        recommendations = ["No configured session health thresholds were exceeded."]
    else:
        finding_types = set(health_findings["Finding"])
        recommendations = []
        if "LONG RUNNING" in finding_types:
            recommendations.append("Review long-running sessions for expected application behavior and idle-timeout requirements.")
        if "VERY HIGH BANDWIDTH" in finding_types:
            recommendations.append("Validate high-volume transfers against expected workloads and capacity limits.")
        if "HIGH THROUGHPUT" in finding_types:
            recommendations.append("Check link utilization and confirm the observed throughput is expected during the incident.")
        if "NOT OFFLOADED" in finding_types:
            recommendations.append("Review each no_ofld_reason and confirm policy, inspection, and hardware-offload eligibility.")
    incident_summary = "\n".join(
        [
            f"Sessions analyzed: {count:,}",
            f"Top source IP: {top_source}",
            f"Top destination IP: {top_destination}",
            f"Highest bandwidth session: {highest_label}",
            f"Longest active session: {longest_label}",
            f"HTTP sessions: {http_count:,}",
            f"HTTPS sessions: {https_count:,}",
            f"Sessions not hardware accelerated: {not_offloaded:,}",
            "Key findings:",
            *([f"- {name}: {int((health_findings['Finding'] == name).sum()):,}" for name in sorted(set(health_findings["Finding"]))] if not health_findings.empty else ["- No threshold findings."]),
            "Recommendations:",
            *(f"- {recommendation}" for recommendation in recommendations),
        ]
    )
    return SessionAnalysis(
        sessions,
        summary,
        top_talkers,
        longest_sessions,
        source_analysis,
        destination_analysis,
        health_findings,
        incident_summary,
    )


def build_session_excel_report(analysis: SessionAnalysis) -> BytesIO:
    """Create the requested multi-sheet incident workbook in memory."""
    summary = pd.DataFrame(
        [{"Metric": key, "Value": value} for key, value in analysis.summary.items()]
    )
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
        analysis.sessions.to_excel(writer, sheet_name="All Sessions", index=False)
        analysis.top_talkers.to_excel(writer, sheet_name="Top Talkers", index=False)
        analysis.longest_sessions.to_excel(writer, sheet_name="Longest Sessions", index=False)
        analysis.source_analysis.to_excel(writer, sheet_name="Source Analysis", index=False)
        analysis.destination_analysis.to_excel(writer, sheet_name="Destination Analysis", index=False)
        analysis.health_findings.to_excel(writer, sheet_name="Health Findings", index=False)
    output.seek(0)
    return output