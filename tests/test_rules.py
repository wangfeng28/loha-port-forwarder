import unittest

from loha.rules import (
    add_alias,
    add_port_rule,
    parse_port_spec,
    parse_rules_text,
    prune_port_rules,
    remove_port_rule,
)
from loha.exceptions import RulesValidationError


class RulesTests(unittest.TestCase):
    def test_plus_offset_normalizes_to_range(self):
        spec = parse_port_spec("5001+99", allow_plus=True)
        self.assertEqual("5001-5100", spec.canonical)

    def test_rules_parser_rejects_overlap(self):
        with self.assertRaises(RulesValidationError):
            parse_rules_text(
                "ALIAS\tVM_WEB\t192.168.10.20\n"
                "PORT\ttcp\t8080\tVM_WEB\t80\n"
                "PORT\ttcp\t8080-8085\tVM_WEB\t8080-8085\n"
            )

    def test_prune_requires_full_range_containment(self):
        rules = parse_rules_text(
            "ALIAS\tVM_WEB\t192.168.10.20\n"
            "PORT\ttcp\t5090-5120\tVM_WEB\t5090-5120\n"
            "PORT\ttcp\t6001-6100\tVM_WEB\t6051-6150\n"
        )
        pruned = prune_port_rules(rules, proto="tcp", range_spec="6001-6100")
        self.assertEqual(1, len(pruned.ports))
        self.assertEqual("5090-5120", pruned.ports[0].listen.canonical)

    def test_add_and_remove_port_round_trip(self):
        rules = add_alias(parse_rules_text(""), "VM_WEB", "192.168.10.20")
        rules = add_port_rule(rules, "tcp", "8080", "VM_WEB", "80")
        self.assertEqual(1, len(rules.ports))
        rules = remove_port_rule(rules, "tcp", "8080")
        self.assertEqual(0, len(rules.ports))


if __name__ == "__main__":
    unittest.main()
