"""Create a multi-sheet Excel report for a firewall policy comparison."""

from __future__ import annotations

from io import BytesIO
from typing import Hashable, Mapping

import pandas as pd

from comparer import ComparisonResult
from parser import POLICY_FIELDS


def display_value(value: object) -> str:
    """Format parsed scalar and list values for tables and Excel cells."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _policy_rows(
    policies: Mapping[Hashable, dict[str, object]],
    review_status_by_policy: Mapping[tuple[str, str], str],
) -> list[dict[str, str]]:
    rows = []
    for policy_key, policy in policies.items():
        policy_type = str(policy.get("policy_type", "Firewall"))
        policy_id = str(policy.get("policyid", policy_key))
        row = {"Policy Type": policy_type, "Policy ID": policy_id}
        row.update(
            {
                field_name.replace("_", " ").title(): display_value(
                    policy.get(field_name)
                )
                for field_name in POLICY_FIELDS
            }
        )
        row["Review Status"] = review_status_by_policy.get(
            (policy_type, policy_id), "Pending Review"
        )
        rows.append(row)
    return rows


def _policy_columns(include_review_status: bool = False) -> list[str]:
    columns = ["Policy Type", "Policy ID"] + [
        field_name.replace("_", " ").title() for field_name in POLICY_FIELDS
    ]
    if include_review_status:
        columns.append("Review Status")
    return columns


def build_excel_report(
    result: ComparisonResult,
    review_status_by_policy: Mapping[tuple[str, str], str] | None = None,
) -> BytesIO:
    """Return an in-memory workbook with summary and policy category sheets."""
    output = BytesIO()
    review_status_by_policy = review_status_by_policy or {}
    review_items = result.policy_review_items
    reviewed_count = sum(
        review_status_by_policy.get(
            (str(item["Policy Type"]), str(item["Policy ID"])), "Pending Review"
        )
        == "Reviewed"
        for item in review_items
    )
    summary_values = {
        **result.summary,
        "Reviewed Changes": reviewed_count,
        "Pending Review Changes": len(review_items) - reviewed_count,
    }
    summary = pd.DataFrame(
        [{"Metric": metric, "Count": count} for metric, count in summary_values.items()]
    )
    modified = pd.DataFrame(
        [
            {
                "Policy ID": change["policyid"],
                "Policy Type": change["policy_type"],
                "Policy Name": change["name"] or "",
                "Changed Field": change["field"],
                "Before Value": display_value(change["before"]),
                "After Value": display_value(change["after"]),
                "Review Status": review_status_by_policy.get(
                    (str(change["policy_type"]), str(change["policyid"])),
                    "Pending Review",
                ),
            }
            for change in result.modified
        ],
        columns=[
            "Policy ID",
            "Policy Type",
            "Policy Name",
            "Changed Field",
            "Before Value",
            "After Value",
            "Review Status",
        ],
    )

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
        pd.DataFrame(
            _policy_rows(result.added, review_status_by_policy),
            columns=_policy_columns(include_review_status=True),
        ).to_excel(
            writer, sheet_name="Added Policies", index=False
        )
        pd.DataFrame(
            _policy_rows(result.removed, review_status_by_policy),
            columns=_policy_columns(include_review_status=True),
        ).to_excel(
            writer, sheet_name="Removed Policies", index=False
        )
        modified.to_excel(writer, sheet_name="Modified Policies", index=False)
        pd.DataFrame(
            _policy_rows(result.unchanged, review_status_by_policy),
            columns=_policy_columns(),
        ).to_excel(
            writer, sheet_name="Unchanged Policies", index=False
        )

    output.seek(0)
    return output