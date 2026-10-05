import unittest

from ha_consistency import (
    HAChange,
    build_ha_excel_report,
    build_ha_html_report,
    build_ha_pdf_report,
    compare_ha_configurations,
    exact_differences,
    render_ha_object_html,
)


BASE_CONFIG = '''config system global
 set hostname firewall-a
end
config system interface
 edit port1
  set ip 10.0.0.1 255.255.255.0
 next
end
config firewall address
 edit LAN
  set subnet 10.10.0.0 255.255.255.0
 next
end
config firewall service custom
 edit WEB
  set tcp-portrange 80
 next
end
config firewall policy
 edit 10
  set srcaddr LAN
  set dstaddr all
  set service WEB
  set nat enable
  set comments "approved"
 next
 edit 20
  set srcaddr LAN
  set dstaddr all
  set service WEB
 next
end
'''


class HAConsistencyTests(unittest.TestCase):
    def test_ignores_device_local_settings(self):
        peer_config = BASE_CONFIG.replace("firewall-a", "firewall-b").replace(
            "10.0.0.1 255.255.255.0", "10.0.0.2 255.255.255.0"
        )

        result = compare_ha_configurations(BASE_CONFIG, peer_config)

        self.assertEqual(result.health_score, 100)
        self.assertEqual(result.different_count, 0)
        self.assertEqual(result.missing_count, 0)

    def test_classifies_service_address_nat_and_comment_changes(self):
        service_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace("set service WEB", "set service ALL", 1)
        )
        self.assertEqual(service_result.different_count, 1)
        service_change = next(change for change in service_result.changes if change.status == "Modified")
        self.assertEqual(service_change.risk, "Medium")
        self.assertEqual(
            exact_differences(service_change)[0]["Difference"], "WEB -> ALL"
        )
        self.assertTrue(service_change.impact)
        self.assertTrue(service_change.recommendation)

        address_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace("set srcaddr LAN", "set srcaddr MISSING", 1)
        )
        address_change = next(change for change in address_result.changes if change.status == "Modified")
        self.assertEqual(address_change.risk, "Medium")
        self.assertTrue(address_result.dependencies)

        nat_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace("set nat enable", "set nat disable", 1)
        )
        nat_change = next(change for change in nat_result.changes if change.status == "Modified")
        self.assertEqual(nat_change.risk, "High")

        comment_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace('set comments "approved"', 'set comments "reviewed"')
        )
        self.assertEqual(comment_result.health_score, 100)
        self.assertEqual(comment_result.different_count, 0)
        self.assertEqual(comment_result.cosmetic_count, 1)

        uuid_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace(" edit LAN\n", " edit LAN\n  set uuid 1234\n", 1)
        )
        self.assertEqual(uuid_result.health_score, 100)
        self.assertEqual(uuid_result.cosmetic_count, 1)

        metadata_result = compare_ha_configurations(
            BASE_CONFIG,
            BASE_CONFIG.replace(" edit LAN\n", " edit LAN\n  set build 1234\n  set timestamp now\n", 1),
        )
        self.assertEqual(metadata_result.health_score, 100)
        self.assertEqual(metadata_result.cosmetic_count, 0)

    def test_detects_policy_order_and_missing_dependencies(self):
        reordered = BASE_CONFIG.replace(
            " edit 10\n  set srcaddr LAN\n  set dstaddr all\n  set service WEB\n  set nat enable\n  set comments \"approved\"\n next\n edit 20",
            " edit 20\n  set srcaddr LAN\n  set dstaddr all\n  set service WEB\n next\n edit 10\n  set srcaddr LAN\n  set dstaddr all\n  set service WEB\n  set nat enable\n  set comments \"approved\"",
        )
        with_missing_service = BASE_CONFIG.replace("set service WEB", "set service NOT-DEFINED", 1)

        order_result = compare_ha_configurations(BASE_CONFIG, reordered)
        sequence_result = compare_ha_configurations(
            BASE_CONFIG,
            reordered.replace(" edit 10\n", " edit 562\n").replace(
                " edit 20\n", " edit 767\n"
            ),
            policy_match_mode="Sequence Validation",
        )
        dependency_result = compare_ha_configurations(BASE_CONFIG, with_missing_service)
        missing_policy_result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace(" edit 20\n  set srcaddr LAN\n  set dstaddr all\n  set service WEB\n next\n", "")
        )

        self.assertTrue(order_result.order_changes)
        self.assertEqual(sequence_result.equivalent_policy_count, 2)
        self.assertEqual(len(sequence_result.order_changes), 2)
        self.assertLess(order_result.health_score, 100)
        self.assertEqual(missing_policy_result.missing_policy_count, 1)
        self.assertTrue(
            any(item["Missing Reference"] == "NOT-DEFINED" for item in dependency_result.dependencies)
        )

    def test_functional_mode_matches_policies_with_different_ids(self):
        firewall_a = BASE_CONFIG.replace(" edit 10\n", " edit 562\n", 1)
        firewall_b = BASE_CONFIG.replace(" edit 10\n", " edit 767\n", 1)

        id_result = compare_ha_configurations(firewall_a, firewall_b)
        functional_result = compare_ha_configurations(
            firewall_a, firewall_b, policy_match_mode="Functional Match"
        )

        self.assertEqual(id_result.missing_policy_count, 2)
        self.assertEqual(functional_result.missing_policy_count, 0)
        self.assertEqual(functional_result.equivalent_policy_count, 1)
        self.assertEqual(functional_result.exact_policy_count, 1)
        self.assertEqual(functional_result.health_score, 100)
        equivalent = next(
            change for change in functional_result.changes if change.status == "Equivalent"
        )
        self.assertEqual(equivalent.before_object_id, "562")
        self.assertEqual(equivalent.after_object_id, "767")
        self.assertEqual(exact_differences(equivalent), [])

    def test_keeps_dependencies_scoped_to_vdom(self):
        config = '''config vdom
 edit root
  config firewall address
   edit LAN
    set subnet 10.10.0.0 255.255.255.0
   next
  end
 next
 edit customer
  config firewall policy
   edit 10
    set srcaddr LAN
    set dstaddr all
    set service ALL
   next
  end
 next
end
'''

        result = compare_ha_configurations(config, config)

        self.assertTrue(
            any(item["Missing Reference"] == "LAN" for item in result.dependencies)
        )

    def test_side_by_side_view_shows_differences_and_missing_placeholder(self):
        change = HAChange(
            "Firewall Policies",
            "10",
            "Web Access",
            "Modified",
            ("set service WEB", "set schedule always"),
            ("set service HTTP", "set schedule always"),
        )

        comparison = render_ha_object_html(change)
        missing_object = render_ha_object_html(
            HAChange(
                "Address Objects",
                "DMZ",
                "DMZ",
                "Missing in Firewall B",
                ("set subnet 10.1.0.0 255.255.255.0",),
                (),
            )
        )

        self.assertIn("set&nbsp;service", comparison)
        self.assertNotIn("set&nbsp;schedule&nbsp;always", comparison)
        self.assertIn("&lt;OBJECT&nbsp;MISSING&gt;", missing_object)
        self.assertIn("Pre-Change", comparison)
        self.assertIn("Post-Change", comparison)
        self.assertIn("#D4F8D4", comparison)
        self.assertIn("#FFD6D6", comparison)
        self.assertIn("#FFF1B8", comparison)

    def test_generates_html_excel_and_pdf_reports(self):
        result = compare_ha_configurations(
            BASE_CONFIG, BASE_CONFIG.replace("set service WEB", "set service ALL", 1)
        )

        html_report = build_ha_html_report(result)
        self.assertIn(b"FortiGate HA Configuration Consistency", html_report)
        self.assertIn(b"Impact Assessment", html_report)
        self.assertIn(b"Recommended Action", html_report)
        self.assertIn(b"WEB", html_report)
        self.assertIn(b"ALL", html_report)
        report_text = html_report.decode("utf-8")
        summary_start = report_text.index("<h2>Object Differences</h2>")
        self.assertLess(
            report_text.index("</table>", summary_start),
            report_text.index("<h3>", summary_start),
        )
        self.assertIn(b"diff_chg", html_report)
        self.assertGreater(len(build_ha_excel_report(result).getvalue()), 0)
        self.assertTrue(build_ha_pdf_report(result).startswith(b"%PDF"))

    def test_cosmetic_differences_are_reported_separately(self):
        result = compare_ha_configurations(
            BASE_CONFIG,
            BASE_CONFIG.replace('set comments "approved"', 'set comments "reviewed"'),
        )

        html_report = build_ha_html_report(result)

        self.assertEqual(result.health_score, 100)
        self.assertIn(b"Cosmetic Differences", html_report)
        self.assertIn(b"approved", html_report)
        self.assertIn(b"reviewed", html_report)


if __name__ == "__main__":
    unittest.main()