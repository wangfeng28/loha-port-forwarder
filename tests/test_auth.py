import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

from loha.auth import plan_auth_mode_switch, plan_selected_auth_mode_switch, survey_auth_mark_candidates
from loha.system import SystemAdapter


class FakeAdapter(SystemAdapter):
    def __init__(
        self,
        ruleset: str = "",
        *,
        label_probe_ok: bool = True,
        nf_conntrack_text: str = "",
        conntrack_listing: str = "",
    ):
        self.ruleset = ruleset
        self.label_probe_ok = label_probe_ok
        self.nf_conntrack_text = nf_conntrack_text
        self.conntrack_listing = conntrack_listing

    def command_exists(self, name: str) -> bool:
        return name in {"nft"} or (name == "conntrack" and bool(self.conntrack_listing))

    def run(self, argv, *, input_text: str = "", check: bool = True):
        if tuple(argv) == ("nft", "-c", "-f", "-"):
            return CompletedProcess(argv, 0 if self.label_probe_ok else 1, stdout="", stderr="")
        if tuple(argv) == ("nft", "list", "ruleset"):
            return CompletedProcess(argv, 0, stdout=self.ruleset, stderr="")
        if tuple(argv) == ("conntrack", "-L", "-o", "extended"):
            return CompletedProcess(argv, 0, stdout=self.conntrack_listing, stderr="")
        raise AssertionError(f"unexpected command: {argv}")

    def default_ipv4_ifaces(self):
        return ()

    def list_interfaces(self):
        return ()

    def global_ipv4s(self, interface: str):
        return ()

    def ipv4_networks(self, interface: str):
        return ()

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise AssertionError("not used")

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("not used")

    def scan_listeners(self):
        return set()

    def read_text(self, path: Path) -> str:
        if str(path) == "/proc/net/nf_conntrack":
            if self.nf_conntrack_text:
                return self.nf_conntrack_text
            raise FileNotFoundError(path)
        return path.read_text(encoding="utf-8")


class AuthModeTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return type("Paths", (), {"debug_ruleset_file": temp_dir / "loha_debug.nft", "service_unit": temp_dir / "loha.service"})()

    def test_same_mark_mode_reports_already_configured(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "mark",
            paths=self._paths(),
            adapter=FakeAdapter(),
        )
        self.assertFalse(plan.changed)
        self.assertIn("already ct mark", plan.message.render())

    def test_switch_to_label_picks_next_free_label_when_default_conflicts(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "label",
            paths=self._paths(),
            adapter=FakeAdapter(
                ruleset=(
                    "table inet firewall {\n"
                    "    chain input {\n"
                    "        type filter hook input priority 0; policy accept;\n"
                    "        ct label set 56\n"
                    "    }\n"
                    "}\n"
                )
            ),
        )
        self.assertTrue(plan.changed)
        self.assertEqual("label", plan.auth_mode)
        self.assertEqual("57", plan.dnat_label)
        self.assertEqual("", plan.dnat_mark)

    def test_switch_to_label_ignores_loha_owned_debug_snapshot_label_reference(self):
        paths = self._paths()
        paths.debug_ruleset_file.write_text("ct label set 56\n", encoding="utf-8")
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "label",
            paths=paths,
            adapter=FakeAdapter(),
        )
        self.assertEqual("56", plan.dnat_label)

    def test_switch_to_mark_avoids_used_mark_candidates(self):
        paths = self._paths()
        paths.debug_ruleset_file.write_text("define DNAT_MARK = 0x10000000\n", encoding="utf-8")
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            "mark",
            paths=paths,
            adapter=FakeAdapter(),
        )
        self.assertTrue(plan.changed)
        self.assertEqual("mark", plan.auth_mode)
        self.assertEqual("0x10000000", plan.dnat_mark)
        self.assertEqual("", plan.dnat_label)
        self.assertIsNotNone(plan.reload_hint)
        self.assertIn("reload --full", plan.reload_hint.render())

    def test_switch_to_mark_avoids_runtime_conntrack_mark_conflicts(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            "mark",
            paths=self._paths(),
            adapter=FakeAdapter(nf_conntrack_text="tcp 6 1 mark=0x10000000 use=1\n"),
        )
        self.assertEqual("0x40000000", plan.dnat_mark)

    def test_same_mark_mode_ignores_existing_loha_runtime_mark(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "mark",
            paths=self._paths(),
            adapter=FakeAdapter(nf_conntrack_text="tcp 6 1 mark=0x10000000 use=1\n"),
        )
        self.assertFalse(plan.changed)
        self.assertEqual("0x10000000", plan.dnat_mark)

    def test_switch_to_label_warns_when_ct_label_probe_fails(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "label",
            paths=self._paths(),
            adapter=FakeAdapter(label_probe_ok=False),
        )
        self.assertIn("ct label capability probe failed", plan.warnings[0].render())

    def test_selected_mark_plan_uses_explicit_choice_without_cli_rebuilding_messages(self):
        plan = plan_selected_auth_mode_switch(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            "mark",
            selected_mark="0x20000000",
            paths=self._paths(),
            adapter=FakeAdapter(),
        )
        self.assertTrue(plan.changed)
        self.assertEqual("mark", plan.auth_mode)
        self.assertEqual("0x20000000", plan.dnat_mark)
        self.assertIn("switched to ct mark", plan.message.render())
        self.assertIsNotNone(plan.reload_hint)

    def test_selected_label_plan_preserves_probe_warnings(self):
        plan = plan_selected_auth_mode_switch(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            "label",
            selected_label="88",
            paths=self._paths(),
            adapter=FakeAdapter(label_probe_ok=False),
        )
        self.assertEqual("88", plan.dnat_label)
        self.assertIn("ct label capability probe failed", plan.warnings[0].render())

    def test_mark_survey_reports_available_and_conflicting_candidates(self):
        survey = survey_auth_mark_candidates(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            paths=self._paths(),
            adapter=FakeAdapter(nf_conntrack_text="tcp 6 1 mark=0x10000000 use=1\n"),
        )
        self.assertEqual("0x40000000", survey.suggested_mark)
        self.assertIn("0x10000000", survey.conflicting_marks)
        self.assertIn("0x40000000", survey.available_marks)
        self.assertTrue(survey.runtime_scan_available)
        self.assertEqual((), survey.static_conflicting_marks)
        self.assertEqual(("0x10000000",), survey.runtime_conflicting_marks)
        self.assertEqual(("0x10000000",), survey.runtime_conflict_samples)

    def test_mark_survey_ignores_loha_owned_live_table_static_mark_references(self):
        survey = survey_auth_mark_candidates(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            paths=self._paths(),
            adapter=FakeAdapter(
                ruleset=(
                    "table ip loha_port_forwarder {\n"
                    "    chain port_forwarding {\n"
                    "        ct mark set ct mark and 0xEFFFFFFF\n"
                    "    }\n"
                    "    chain forward {\n"
                    "        ct status dnat ct mark & 0x10000000 != 0 accept\n"
                    "    }\n"
                    "}\n"
                )
            ),
        )
        self.assertEqual((), survey.static_conflicting_marks)
        self.assertEqual((), survey.static_conflict_samples)

    def test_mark_survey_reports_external_clear_mask_as_single_bit_conflict(self):
        survey = survey_auth_mark_candidates(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            paths=self._paths(),
            adapter=FakeAdapter(
                ruleset=(
                    "table inet firewall {\n"
                    "    chain prerouting {\n"
                    "        type filter hook prerouting priority 0; policy accept;\n"
                    "        ct mark set ct mark and 0xEFFFFFFF\n"
                    "    }\n"
                    "}\n"
                )
            ),
        )
        self.assertEqual(("0x10000000",), survey.static_conflicting_marks)
        self.assertEqual(("0xEFFFFFFF",), survey.static_conflict_samples)

    def test_switch_to_mark_avoids_external_nft_mark_conflicts(self):
        plan = plan_auth_mode_switch(
            {
                "AUTH_MODE": "label",
                "DNAT_MARK": "",
                "DNAT_LABEL": "56",
            },
            "mark",
            paths=self._paths(),
            adapter=FakeAdapter(
                ruleset=(
                    "table inet firewall {\n"
                    "    chain prerouting {\n"
                    "        type filter hook prerouting priority 0; policy accept;\n"
                    "        meta mark set meta mark or 0x10000000\n"
                    "    }\n"
                    "}\n"
                )
            ),
        )
        self.assertEqual("0x40000000", plan.dnat_mark)

    def test_mark_survey_reports_runtime_composite_mark_samples(self):
        survey = survey_auth_mark_candidates(
            {
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
                "DNAT_LABEL": "",
            },
            paths=self._paths(),
            adapter=FakeAdapter(nf_conntrack_text="tcp 6 1 mark=0x6FC00000 use=1\n"),
        )
        self.assertEqual("0x10000000", survey.suggested_mark)
        self.assertEqual(
            (
                "0x40000000",
                "0x20000000",
                "0x08000000",
                "0x04000000",
                "0x02000000",
                "0x01000000",
                "0x00800000",
                "0x00400000",
            ),
            survey.runtime_conflicting_marks,
        )
        self.assertEqual(("0x6FC00000",), survey.runtime_conflict_samples)


if __name__ == "__main__":
    unittest.main()
