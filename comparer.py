"""Compare parsed firewall policy collections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Mapping

from deepdiff import DeepDiff

from parser import POLICY_FIELDS, POLICY_SECTIONS


Policy = dict[str, object]
PolicyKey = Hashable


@dataclass
class ComparisonResult:
    """Categorized policy comparison and row-level field changes."""

    before: Mapping[PolicyKey, Policy]
    after: Mapping[PolicyKey, Policy]
    added: dict[PolicyKey, Policy]
    removed: dict[PolicyKey, Policy]
    modified: list[dict[str, object]]
    unchanged: dict[PolicyKey, Policy]

    @staticmethod
    def policy_type(key: PolicyKey, policy: Policy) -> str:
        if policy.get("policy_type"):
            return str(policy["policy_type"])
        if isinstance(key, tuple) and key:
            return str(key[0])
        return "Firewall"

    @staticmethod
    def policy_id(key: PolicyKey, policy: Policy) -> str:
        if policy.get("policyid") is not None:
            return str(policy["policyid"])
        if isinstance(key, tuple) and len(key) > 1:
            return str(key[1])
        return str(key)

    @property
    def modified_policy_keys(self) -> set[tuple[str, str]]:
        return {
            (str(change["policy_type"]), str(change["policyid"]))
            for change in self.modified
        }

    @property
    def policy_type_counts(self) -> list[dict[str, object]]:
        types = set(POLICY_SECTIONS.values()) | {
            self.policy_type(key, policy)
            for policies in (self.before, self.after)
            for key, policy in policies.items()
        }
        counts = []
        for policy_type in sorted(types):
            before_policies = {
                key
                for key, policy in self.before.items()
                if self.policy_type(key, policy) == policy_type
            }
            after_policies = {
                key
                for key, policy in self.after.items()
                if self.policy_type(key, policy) == policy_type
            }
            counts.append(
                {
                    "Policy Type": policy_type,
                    "Total Before": len(before_policies),
                    "Total After": len(after_policies),
                    "Added": sum(
                        self.policy_type(key, policy) == policy_type
                        for key, policy in self.added.items()
                    ),
                    "Removed": sum(
                        self.policy_type(key, policy) == policy_type
                        for key, policy in self.removed.items()
                    ),
                    "Modified": len(
                        {
                            (str(change["policy_type"]), str(change["policyid"]))
                            for change in self.modified
                            if change["policy_type"] == policy_type
                        }
                    ),
                    "Unchanged": sum(
                        self.policy_type(key, policy) == policy_type
                        for key, policy in self.unchanged.items()
                    ),
                }
            )
        return counts

    @property
    def policy_review_items(self) -> list[dict[str, object]]:
        items: dict[tuple[str, str], dict[str, object]] = {}
        for category, policies in (("Added", self.added), ("Removed", self.removed)):
            for key, policy in policies.items():
                policy_type = self.policy_type(key, policy)
                policy_id = self.policy_id(key, policy)
                items[(policy_type, policy_id)] = {
                    "Policy Type": policy_type,
                    "Policy ID": policy_id,
                    "Policy Name": policy.get("name") or "",
                    "Change Type": category,
                    "Changed Fields": f"Policy {category.lower()}",
                }
        modified_fields: dict[tuple[str, str], set[str]] = {}
        for change in self.modified:
            review_key = (str(change["policy_type"]), str(change["policyid"]))
            modified_fields.setdefault(review_key, set()).add(str(change["field"]))
            items[review_key] = {
                "Policy Type": review_key[0],
                "Policy ID": review_key[1],
                "Policy Name": change["name"] or "",
                "Change Type": "Modified",
                "Changed Fields": "",
            }
        for review_key, fields in modified_fields.items():
            items[review_key]["Changed Fields"] = ", ".join(sorted(fields))
        return [items[key] for key in sorted(items)]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "Total Policies Before": len(self.before),
            "Total Policies After": len(self.after),
            "Added Policies Count": len(self.added),
            "Removed Policies Count": len(self.removed),
            "Modified Policies Count": len(self.modified_policy_keys),
            "Unchanged Policies Count": len(self.unchanged),
            "Total Policies Changed": (
                len(self.added) + len(self.removed) + len(self.modified_policy_keys)
            ),
        }


def compare_policies(
    before: Mapping[PolicyKey, Policy], after: Mapping[PolicyKey, Policy]
) -> ComparisonResult:
    """Match policies by ID and identify policy-level and field-level changes."""
    before_ids = set(before)
    after_ids = set(after)
    added_keys = sorted(
        after_ids - before_ids,
        key=lambda key: (
            ComparisonResult.policy_type(key, after[key]),
            ComparisonResult.policy_id(key, after[key]),
        ),
    )
    removed_keys = sorted(
        before_ids - after_ids,
        key=lambda key: (
            ComparisonResult.policy_type(key, before[key]),
            ComparisonResult.policy_id(key, before[key]),
        ),
    )
    added = {key: after[key] for key in added_keys}
    removed = {key: before[key] for key in removed_keys}
    modified: list[dict[str, object]] = []
    unchanged: dict[PolicyKey, Policy] = {}

    matched_keys = sorted(
        before_ids & after_ids,
        key=lambda key: (
            ComparisonResult.policy_type(key, after[key]),
            ComparisonResult.policy_id(key, after[key]),
        ),
    )
    for policy_key in matched_keys:
        previous = before[policy_key]
        current = after[policy_key]
        policy_type = ComparisonResult.policy_type(policy_key, current)
        policy_id = ComparisonResult.policy_id(policy_key, current)
        previous_fields = {key: previous.get(key) for key in POLICY_FIELDS}
        current_fields = {key: current.get(key) for key in POLICY_FIELDS}
        diff = DeepDiff(previous_fields, current_fields, ignore_order=True)

        if not diff:
            unchanged[policy_key] = current
            continue

        for field_name in POLICY_FIELDS:
            field_diff = DeepDiff(
                {field_name: previous.get(field_name)},
                {field_name: current.get(field_name)},
                ignore_order=True,
            )
            if field_diff:
                modified.append(
                    {
                        "policyid": policy_id,
                        "policy_type": policy_type,
                        "name": current.get("name") or previous.get("name"),
                        "field": field_name,
                        "before": previous.get(field_name),
                        "after": current.get(field_name),
                    }
                )

    return ComparisonResult(
        before=before,
        after=after,
        added=added,
        removed=removed,
        modified=modified,
        unchanged=unchanged,
    )