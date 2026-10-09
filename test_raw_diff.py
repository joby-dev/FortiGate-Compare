import unittest

from raw_diff import (
    DiffHunk,
    build_raw_html_report,
    build_unified_diff,
    compare_raw_configurations,
    render_side_by_side_document,
)


class RawConfigurationDiffTests(unittest.TestCase):
    def test_full_configuration_diff_and_exports(self):
        before = """config system global
 set hostname firewall-a
     set timezone 04
end
config firewall policy
 edit 10
  set srcaddr cloud_publishers
 next
end
"""
        after = before.replace("firewall-a", "firewall-b").replace(
            "cloud_publishers", "cloud_publisher"
        )

        result = compare_raw_configurations(
            before, after, "firewall-a.conf", "firewall-b.conf"
        )
        changed_rows = [
            row for hunk in result.hunks for row in hunk.rows if row.kind != "Unchanged"
        ]
        viewer = render_side_by_side_document(
            result.hunks[0],
            result.before_name,
            result.after_name,
            {"Added", "Removed", "Modified"},
            max_rows=5000,
        )
        ha_viewer = render_side_by_side_document(
            result.hunks[0],
            result.before_name,
            result.after_name,
            max_rows=5000,
            before_label="Firewall A",
            after_label="Firewall B",
        )
        unified = build_unified_diff(result)
        html_report = build_raw_html_report(result).decode("utf-8")

        self.assertTrue(changed_rows)
        self.assertTrue(result.before_spans)
        policy_span = next(
            span for span in result.before_spans if span.object_id == "10"
        )
        self.assertEqual(policy_span.name, "10")
        self.assertGreater(policy_span.end, policy_span.start)
        self.assertIn("FIREWALL A / PRE-CHANGE", viewer)
        self.assertIn("FIREWALL B / POST-CHANGE", viewer)
        self.assertIn("FIREWALL A:", ha_viewer)
        self.assertIn("FIREWALL B:", ha_viewer)
        self.assertIn("cloud_publisher", viewer)
        self.assertIn("cloud_publishers", viewer)
        self.assertIn("Previous Difference", viewer)
        self.assertIn("Difference '+(activeIndex+1)+' of '+blocks.length", viewer)
        self.assertIn("id='navigator'", viewer)
        self.assertIn("monaco.editor.createDiffEditor", viewer)
        self.assertIn("wordWrap:'off'", viewer)
        self.assertIn("aOriginalStart", viewer)
        self.assertIn("Sync Scrolling", viewer)
        self.assertIn("leftTop:left.getScrollTop()", viewer)
        self.assertIn("rightTop:right.getScrollTop()", viewer)
        self.assertIn("left.setScrollTop(saved.leftTop)", viewer)
        self.assertIn("syncToggle.checked", viewer)
        self.assertNotIn("followVisibleBlock", viewer)
        self.assertNotIn("if(nearest!==activeIndex)goTo(nearest)", viewer)
        self.assertNotIn("diff.onDidUpdateDiff", viewer)
        self.assertNotIn("scrollTop=source.scrollTop", viewer)
        self.assertIn("overflow:auto", viewer)
        self.assertIn("firewall-a", unified)
        self.assertIn("cloud_publisher", unified)
        self.assertIn("#EAF6FF", html_report)
        self.assertIn("#FFF1B8", html_report)
        self.assertTrue(
            any(
                row.kind == "Unchanged" and "set timezone 04" in row.before_text
                for row in result.full_rows
            )
        )

    def test_monaco_viewer_keeps_fifty_thousand_source_lines(self):
        before_lines = [f"set value {index}" for index in range(50000)]
        after_lines = list(before_lines)
        after_lines[25000] = "set value changed"
        viewer = render_side_by_side_document(
            DiffHunk("large file", set(), set(), []),
            "a.conf",
            "b.conf",
            source_before_lines=before_lines,
            source_after_lines=after_lines,
        )

        self.assertIn("set value 49999", viewer)
        self.assertIn("set value changed", viewer)
        self.assertIn("monaco.editor.createDiffEditor", viewer)

    def test_selected_object_jump_is_one_shot_and_marks_missing_peer(self):
        viewer = render_side_by_side_document(
            DiffHunk("policy", set(), set(), []),
            "a.conf",
            "b.conf",
            source_before_lines=["config firewall policy", " edit 890", "  set name Azure", " next"],
            source_after_lines=["config firewall policy", " edit 891", "  set name Other", " next"],
            storage_key="comparison-test",
            navigation_target={
                "token": "jump-1",
                "label": "Azure Prod",
                "status": "Missing in B",
                "before": {"start": 1, "end": 3, "start_line": 2},
                "after": None,
            },
            navigation_before_line=2,
        )

        self.assertIn("selected-object-flash", viewer)
        self.assertIn("<Policy Missing>", viewer)
        self.assertIn("navigationTarget.token", viewer)
        self.assertIn("storageKey+':jump'", viewer)
        self.assertIn("const navigationBeforeLine=2", viewer)
        self.assertIn("editor.revealLineInCenter(start)", viewer)
        self.assertIn("setTimeout(()=>editor.deltaDecorations(old,[]),3000)", viewer)

    def test_selected_policy_navigation_uses_both_peer_lines(self):
        viewer = render_side_by_side_document(
            DiffHunk("policy", set(), set(), []),
            "a.conf",
            "b.conf",
            source_before_lines=["config firewall policy", " edit 10", " next"],
            source_after_lines=["config firewall policy", " edit 90", " next"],
            navigation_target={
                "token": "policy-jump",
                "before": {"start": 1, "end": 2},
                "after": {"start": 1, "end": 2},
            },
            navigation_before_line=2,
            navigation_after_line=2,
        )

        self.assertIn("const navigationBeforeLine=2", viewer)
        self.assertIn("const navigationAfterLine=2", viewer)
        self.assertIn("highlight(left,beforeSpan,aLine);highlight(right,afterSpan,bLine);", viewer)

    def test_optional_ignore_filters_mask_selected_configuration_lines(self):
        before = '''set config-version 1
config system global
 set hostname firewall-a
 set uuid global-a
 set comments "before"
end
config system interface
 edit port1
  set ip 10.0.0.1 255.255.255.0
 next
end
config system ha
 set mode a-p
 set group-name cluster-a
end
'''
        after = before.replace("config-version 1", "config-version 2").replace(
            "firewall-a", "firewall-b"
        ).replace("global-a", "global-b").replace("before", "after").replace(
            "10.0.0.1", "10.0.0.2"
        ).replace("cluster-a", "cluster-b")

        result = compare_raw_configurations(
            before,
            after,
            ignore_categories={
                "Hostname",
                "Interface IP",
                "UUID",
                "Comments",
                "Config Revisions",
                "HA Settings",
            },
        )

        self.assertEqual(result.hunks, [])


if __name__ == "__main__":
    unittest.main()