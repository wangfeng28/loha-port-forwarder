import unittest

from loha.exceptions import ApplyError
from loha.runtime_binding import (
    describe_binding_status,
    materialize_toggle_shortcut,
    materialize_runtime_binding_values,
    resolve_runtime_binding,
    sync_runtime_binding_state,
    sync_toggle_shortcut_state,
    runtime_binding_summary_lines,
    runtime_binding_doctor_results,
    runtime_binding_persist_notices,
)
from loha.system import SystemAdapter


class FakeAdapter(SystemAdapter):
    def command_exists(self, name: str) -> bool:
        return True

    def run(self, argv, *, input_text: str = "", check: bool = True):
        raise AssertionError("not used")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("lo", "eth0", "eth1")

    def global_ipv4s(self, interface: str):
        return {
            "eth0": ("203.0.113.10", "203.0.113.11"),
            "eth1": ("198.51.100.20",),
        }.get(interface, ())

    def ipv4_networks(self, interface: str):
        return ()

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise AssertionError("not used")

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("not used")

    def scan_listeners(self):
        return set()


class MultiRouteAdapter(FakeAdapter):
    def default_ipv4_ifaces(self):
        return ("eth0", "eth2")


class RuntimeBindingTests(unittest.TestCase):
    def test_materialize_toggle_shortcut_maps_auto_to_recommended_value(self):
        self.assertEqual("on", materialize_toggle_shortcut("auto", "on"))
        self.assertEqual("on", materialize_toggle_shortcut("", "on"))
        self.assertEqual("off", materialize_toggle_shortcut("no", "on"))

    def test_sync_toggle_shortcut_state_flushes_toggle_autos(self):
        updated = sync_toggle_shortcut_state(
            {
                "ENABLE_HAIRPIN": "auto",
                "ENABLE_WAN_TO_WAN": "auto",
                "ENABLE_TCPMSS_CLAMP": "auto",
            }
        )
        self.assertEqual("on", updated["ENABLE_HAIRPIN"])
        self.assertEqual("off", updated["ENABLE_WAN_TO_WAN"])
        self.assertEqual("off", updated["ENABLE_TCPMSS_CLAMP"])

    def test_materializes_auto_shortcuts_without_persisting_auto(self):
        values = materialize_runtime_binding_values(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
        )
        self.assertEqual("eth0", values["EXTERNAL_IFS"])
        self.assertEqual("eth0", values["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("203.0.113.10,203.0.113.11", values["LISTEN_IPS"])
        self.assertEqual("203.0.113.10", values["DEFAULT_SNAT_IP"])
        self.assertNotEqual("auto", values["EXTERNAL_IFS"])
        self.assertNotEqual("auto", values["LISTEN_IPS"])

    def test_materializes_auto_shortcuts_from_explicit_primary_external_interface(self):
        values = materialize_runtime_binding_values(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "eth1",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
        )
        self.assertEqual("eth1", values["EXTERNAL_IFS"])
        self.assertEqual("eth1", values["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("198.51.100.20", values["LISTEN_IPS"])
        self.assertEqual("198.51.100.20", values["DEFAULT_SNAT_IP"])

    def test_sync_runtime_binding_state_materializes_shortcuts_and_returns_notices(self):
        state, notices = sync_runtime_binding_state(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
            only_if_shortcuts=True,
        )
        self.assertEqual("eth0", state["EXTERNAL_IFS"])
        self.assertEqual("203.0.113.10,203.0.113.11", state["LISTEN_IPS"])
        self.assertEqual(2, len(notices))

    def test_sync_runtime_binding_state_skips_when_shortcuts_not_present(self):
        state = {
            "EXTERNAL_IFS": "eth0",
            "PRIMARY_EXTERNAL_IF": "eth0",
            "LISTEN_IPS": "203.0.113.10",
            "DEFAULT_SNAT_IP": "203.0.113.10",
        }
        updated, notices = sync_runtime_binding_state(state, FakeAdapter(), only_if_shortcuts=True)
        self.assertEqual(state, updated)
        self.assertEqual((), notices)

    def test_rejects_multi_external_binding_as_out_of_scope(self):
        with self.assertRaises(ApplyError) as ctx:
            resolve_runtime_binding(
                {
                    "EXTERNAL_IFS": "eth0,eth1",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": "203.0.113.10,198.51.100.20",
                    "DEFAULT_SNAT_IP": "203.0.113.10",
                },
                FakeAdapter(),
            )
        self.assertIn("single-external product boundary", str(ctx.exception))

    def test_rejects_explicit_listeners_outside_primary_interface(self):
        with self.assertRaises(ApplyError) as ctx:
            resolve_runtime_binding(
                {
                    "EXTERNAL_IFS": "eth0",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": "198.51.100.20",
                    "DEFAULT_SNAT_IP": "198.51.100.20",
                },
                FakeAdapter(),
            )
        self.assertIn("LISTEN_IPS must belong to PRIMARY_EXTERNAL_IF (eth0)", str(ctx.exception))

    def test_persist_notices_explain_auto_materialization(self):
        resolution = resolve_runtime_binding(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
        )
        notices = runtime_binding_persist_notices(
            {
                "EXTERNAL_IFS": "auto",
                "LISTEN_IPS": "auto",
            },
            resolution,
        )
        self.assertEqual(2, len(notices))
        self.assertIn("EXTERNAL_IFS=auto was resolved to eth0", notices[0].render())
        self.assertIn("LISTEN_IPS=auto was resolved to 203.0.113.10,203.0.113.11", notices[1].render())

    def test_status_description_marks_multi_external_as_out_of_scope(self):
        description = describe_binding_status("external", "eth0,eth1")
        self.assertEqual("out_of_scope_multi", description.status)
        self.assertIn("one external interface", description.message_default)

    def test_status_description_uses_user_facing_invalid_labels(self):
        external = describe_binding_status("external", "bad iface")
        listen = describe_binding_status("listen", "bad ip")
        self.assertEqual("External interface binding is invalid", external.message_default)
        self.assertEqual("Exposure address binding is invalid", listen.message_default)

    def test_summary_lines_include_runtime_binding_statuses(self):
        lines = runtime_binding_summary_lines(
            {
                "EXTERNAL_IFS": "eth0",
                "LISTEN_IPS": "203.0.113.10,203.0.113.11",
            },
            translate=lambda _key, default: default,
        )
        self.assertEqual("External interface binding: compatible now via the configured single-interface binding", lines[0])
        self.assertEqual(
            "Exposure address binding: compatible now via the configured external IP list used for exposure",
            lines[1],
        )

    def test_doctor_results_report_runtime_binding_success(self):
        results = runtime_binding_doctor_results(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
            },
            FakeAdapter(),
        )
        self.assertEqual(2, len(results))
        self.assertEqual("pass", results[0].level)
        self.assertIn("external binding uses configured values", results[0].summary)
        self.assertEqual("pass", results[1].level)
        self.assertIn("listener binding uses configured values", results[1].summary)

    def test_doctor_results_explain_auto_resolution(self):
        results = runtime_binding_doctor_results(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
        )
        self.assertEqual("pass", results[0].level)
        self.assertIn("EXTERNAL_IFS=auto resolves to primary external interface eth0", results[0].summary)
        self.assertEqual("pass", results[1].level)
        self.assertIn("LISTEN_IPS=auto resolves on primary external interface eth0", results[1].summary)

    def test_doctor_results_explain_auto_resolution_from_explicit_primary_interface(self):
        results = runtime_binding_doctor_results(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "eth1",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            FakeAdapter(),
        )
        self.assertEqual("pass", results[0].level)
        self.assertIn("EXTERNAL_IFS=auto resolves to primary external interface eth1", results[0].summary)
        self.assertIn("materialized EXTERNAL_IFS=eth1", results[0].detail)
        self.assertEqual("pass", results[1].level)
        self.assertIn("LISTEN_IPS=auto resolves on primary external interface eth1 (198.51.100.20)", results[1].summary)
        self.assertIn("DEFAULT_SNAT_IP=198.51.100.20", results[1].detail)

    def test_doctor_results_explain_auto_multi_route_failure(self):
        results = runtime_binding_doctor_results(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
            },
            MultiRouteAdapter(),
        )
        self.assertEqual(2, len(results))
        self.assertEqual("fail", results[0].level)
        self.assertIn("EXTERNAL_IFS=auto found multiple default IPv4 egress interfaces (eth0,eth2)", results[0].summary)
        self.assertEqual("fail", results[1].level)
        self.assertIn(
            "LISTEN_IPS=auto cannot resolve safely because EXTERNAL_IFS=auto sees multiple default egress interfaces (eth0,eth2)",
            results[1].summary,
        )

    def test_doctor_results_fail_for_listener_outside_primary_interface(self):
        results = runtime_binding_doctor_results(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
            },
            FakeAdapter(),
        )
        self.assertEqual("pass", results[0].level)
        self.assertEqual("fail", results[1].level)
        self.assertIn("contains addresses outside the primary external interface (eth0)", results[1].summary)


if __name__ == "__main__":
    unittest.main()
