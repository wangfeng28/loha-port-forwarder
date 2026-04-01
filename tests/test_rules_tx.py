import tempfile
import unittest
from pathlib import Path

from loha.config import normalize_mapping, render_canonical_text
from loha.exceptions import RulesLockError
from loha.models import Paths
from loha.rules import add_alias, load_rules, remove_alias
from loha.rules_tx import mutate_rules_transaction, rules_file_lock


class RulesTxTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return Paths(etc_dir=temp_dir / "etc", run_dir=temp_dir / "run")

    def _config(self):
        return normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )

    def test_mutate_rules_transaction_reloads_under_lock_and_writes_atomically(self):
        paths = self._paths()
        config = self._config()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text("", encoding="utf-8")

        mutate_rules_transaction(
            paths,
            config=config,
            source="cli",
            reason="alias-add",
            mutate=lambda current: add_alias(current, "VM_WEB", "192.168.10.20"),
        )

        rules = load_rules(paths.rules_conf)
        self.assertEqual(1, len(rules.aliases))
        self.assertEqual("VM_WEB", rules.aliases[0].name)

    def test_rules_lock_times_out_when_held(self):
        paths = self._paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        with rules_file_lock(paths.rules_conf, timeout_seconds=0.1, poll_interval_seconds=0.01):
            with self.assertRaises(RulesLockError):
                mutate_rules_transaction(
                    paths,
                    config=self._config(),
                    source="cli",
                    reason="alias-rm",
                    mutate=lambda current: remove_alias(current, "VM_WEB"),
                    timeout_seconds=0.02,
                )


if __name__ == "__main__":
    unittest.main()
