import tempfile
import unittest
from pathlib import Path

from loha.config import normalize_mapping, render_canonical_text
from loha.exceptions import HistoryError
from loha.history import (
    capture_snapshot,
    capture_snapshot_if_enabled,
    list_snapshots,
    load_rollback_checkpoint,
    rollback_snapshot,
    write_transaction,
)
from loha.models import Paths
from loha.rules import parse_rules_text, render_rules_text


class HistoryTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return Paths(etc_dir=temp_dir / "etc", run_dir=temp_dir / "run")

    def _config_text(self, snat_ip="203.0.113.10"):
        return render_canonical_text(
            normalize_mapping(
                {
                    "EXTERNAL_IFS": "eth0",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": f"203.0.113.10,{snat_ip}" if snat_ip != "203.0.113.10" else "203.0.113.10",
                    "DEFAULT_SNAT_IP": snat_ip,
                    "LAN_IFS": "br0",
                    "LAN_NETS": "192.168.10.0/24",
                    "PROTECTION_MODE": "backends",
                }
            )
        )

    def test_snapshot_deduplicates_same_content(self):
        paths = self._paths()
        rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=rules, source="test", reason="first")
        capture_snapshot(paths, source="test", reason="manual")
        capture_snapshot(paths, source="test", reason="manual")
        self.assertEqual(1, len(list_snapshots(paths)))

    def test_rollback_restores_previous_files(self):
        paths = self._paths()
        rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(paths, config_text=self._config_text("198.51.100.20"), rules_text=rules, source="test", reason="change")
        rollback_snapshot(paths, "latest")
        self.assertIn('DEFAULT_SNAT_IP="203.0.113.10"', paths.loha_conf.read_text(encoding="utf-8"))

    def test_rollback_updates_separate_checkpoint_without_consuming_regular_history_slot(self):
        paths = self._paths()
        rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(paths, config_text=self._config_text("198.51.100.20"), rules_text=rules, source="test", reason="change")

        rollback_snapshot(paths, "latest")

        snapshots = list_snapshots(paths)
        self.assertEqual(1, len(snapshots))
        checkpoint = load_rollback_checkpoint(paths)
        self.assertIsNotNone(checkpoint)
        self.assertEqual("rollback", checkpoint.source)
        self.assertEqual("checkpoint", checkpoint.reason)
        self.assertIn('DEFAULT_SNAT_IP="198.51.100.20"', checkpoint.path.joinpath("loha.conf").read_text(encoding="utf-8"))

    def test_capture_snapshot_if_enabled_skips_when_history_is_disabled(self):
        paths = self._paths()
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_CONFIG_HISTORY": "off",
            }
        )
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text("", encoding="utf-8")

        snapshot = capture_snapshot_if_enabled(paths, source="installer", reason="install-apply")

        self.assertIsNone(snapshot)
        self.assertEqual([], list_snapshots(paths))

    def test_rollback_preserves_rescue_dir_when_recovery_also_fails(self):
        paths = self._paths()
        rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(paths, config_text=self._config_text("198.51.100.20"), rules_text=rules, source="test", reason="change")

        with self.assertRaises(HistoryError) as ctx:
            rollback_snapshot(paths, "latest", apply_callback=lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        message = str(ctx.exception)
        self.assertIn("rescue files kept in", message)
        rescue_dir = ctx.exception.rescue_dir
        self.assertIsNotNone(rescue_dir)
        self.assertTrue(rescue_dir.exists())

    def test_rollback_restores_pre_rollback_files_when_apply_recovery_succeeds(self):
        paths = self._paths()
        base_rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        changed_rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=base_rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(
            paths,
            config_text=self._config_text("198.51.100.20"),
            rules_text=changed_rules,
            source="test",
            reason="change",
        )

        calls = []

        def flaky_apply():
            calls.append("apply")
            if len(calls) == 1:
                raise RuntimeError("boom")
            return "recovered"

        with self.assertRaises(HistoryError) as ctx:
            rollback_snapshot(paths, "latest", apply_callback=flaky_apply)

        self.assertTrue(ctx.exception.recovered)
        self.assertIsNone(ctx.exception.rescue_dir)
        self.assertIn("previous files were restored", str(ctx.exception))
        self.assertEqual(["apply", "apply"], calls)
        self.assertIn('DEFAULT_SNAT_IP="198.51.100.20"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("ALIAS\tVM_API\t192.0.2.20", paths.rules_conf.read_text(encoding="utf-8"))
        self.assertIsNone(load_rollback_checkpoint(paths))

    def test_rollback_latest_prefers_checkpoint_for_toggle_behavior(self):
        paths = self._paths()
        base_rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        changed_rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=base_rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(
            paths,
            config_text=self._config_text("198.51.100.20"),
            rules_text=changed_rules,
            source="test",
            reason="change",
        )

        first = rollback_snapshot(paths, "latest")
        self.assertEqual("snapshot", first.restored_from)
        self.assertIn('DEFAULT_SNAT_IP="203.0.113.10"', paths.loha_conf.read_text(encoding="utf-8"))

        second = rollback_snapshot(paths, "latest")
        self.assertEqual("rollback_checkpoint", second.restored_from)
        self.assertIn('DEFAULT_SNAT_IP="198.51.100.20"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertEqual(1, len(list_snapshots(paths)))
        checkpoint = load_rollback_checkpoint(paths)
        self.assertIsNotNone(checkpoint)
        self.assertIn('DEFAULT_SNAT_IP="203.0.113.10"', checkpoint.path.joinpath("loha.conf").read_text(encoding="utf-8"))

    def test_regular_write_clears_rollback_checkpoint(self):
        paths = self._paths()
        rules = render_rules_text(parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\n"))
        write_transaction(paths, config_text=self._config_text(), rules_text=rules, source="test", reason="base")
        capture_snapshot(paths, source="test", reason="before-change")
        write_transaction(paths, config_text=self._config_text("198.51.100.20"), rules_text=rules, source="test", reason="change")
        rollback_snapshot(paths, "latest")

        self.assertIsNotNone(load_rollback_checkpoint(paths))

        write_transaction(
            paths,
            config_text=self._config_text("198.51.100.30"),
            rules_text=rules,
            source="test",
            reason="new-change",
        )

        self.assertIsNone(load_rollback_checkpoint(paths))


if __name__ == "__main__":
    unittest.main()
