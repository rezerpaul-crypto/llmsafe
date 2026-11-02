"""Regression cases for container-derived values and in-place dictionary writes."""

import unittest
from pathlib import Path

from llmsafe.rules.dataflow import DataflowRule


class ContainerDataflowTests(unittest.TestCase):
    def flow_lines(self, content):
        return [
            (finding.rule_id, finding.line)
            for finding in DataflowRule().scan(Path("agent.py"), content)
        ]

    def test_extracted_dictionary_scalar_keeps_source_evidence(self):
        content = '''def handle(user_input):
    box = {"command": user_input}
    value = box["command"]
    return eval(value)
'''
        findings = list(DataflowRule().scan(Path("agent.py"), content))
        self.assertEqual([(f.rule_id, f.line) for f in findings], [("FLOW001", 4)])
        self.assertEqual(findings[0].evidence[0].line, 1)
        self.assertIn("user_input", findings[0].evidence[0].message)

    def test_extracted_nested_dictionary_scalar_keeps_taint(self):
        content = '''def handle(user_input):
    box = {"inner": {"command": user_input}}
    inner = box["inner"]
    value = inner["command"]
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_extracted_namespace_attribute_keeps_taint(self):
        content = '''from types import SimpleNamespace
def handle(user_input):
    state = SimpleNamespace(command=user_input)
    value = state.command
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_scalar_snapshot_survives_origin_overwrite(self):
        content = '''def handle(user_input):
    box = {"command": user_input}
    value = box["command"]
    alias = value
    box["command"] = "1+1"
    return eval(alias)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 6)])

    def test_extracted_unknown_value_retains_taint_on_further_field_read(self):
        content = '''def handle(user_input):
    box = {"value": user_input}
    value = box["value"]
    eval(value["command"])
    eval(value.command)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 4), ("FLOW001", 5)])

    def test_extracted_safe_sibling_does_not_inherit_other_fields(self):
        content = '''def handle(user_input):
    box = {"inner": {"dangerous": user_input, "safe": "1+1"}}
    inner = box["inner"]
    value = inner["safe"]
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [])

    def test_clean_scalar_snapshot_is_not_changed_by_later_field_write(self):
        content = '''def handle(user_input):
    box = {"command": "1+1"}
    value = box["command"]
    box["command"] = user_input
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [])

    def test_branch_selected_scalar_preserves_possible_source(self):
        content = '''def handle(user_input, enabled):
    box = {"safe": "1+1", "dangerous": user_input}
    value = box["safe"]
    if enabled:
        value = box["dangerous"]
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 6)])

    def test_inplace_union_mutates_shared_alias(self):
        content = '''def handle(user_input):
    box = {"command": "1+1"}
    alias = box
    alias |= {"command": user_input}
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_inplace_union_keeps_safe_sibling_precise(self):
        content = '''def handle(user_input):
    box = {}
    box |= {"dangerous": user_input, "safe": "1+1"}
    eval(box["safe"])
    eval(box["dangerous"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_inplace_union_overwrites_shared_field(self):
        content = '''def handle(user_input):
    box = {"command": user_input}
    alias = box
    alias |= {"command": "1+1"}
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [])

    def test_conditional_inplace_union_preserves_possible_taint(self):
        content = '''def handle(user_input, enabled):
    box = {"command": "1+1"}
    alias = box
    if enabled:
        alias |= {"command": user_input}
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 6)])

    def test_union_on_multiple_possible_receivers_cannot_clear_taint(self):
        content = '''def handle(user_input, enabled):
    box = {"command": user_input}
    other = {}
    alias = box
    if enabled:
        alias = other
    alias |= {"command": "1+1"}
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 8)])

    def test_inplace_union_unknown_mapping_stays_conservative(self):
        content = '''def handle(user_input):
    box = {"command": "1+1"}
    alias = box
    alias |= user_input
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_inplace_union_iterable_pairs_preserve_shared_taint(self):
        content = '''def handle(user_input):
    box = {}
    alias = box
    alias |= [("command", user_input)]
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_scalar_augmented_assignment_keeps_existing_behavior(self):
        content = '''def handle(user_input):
    value = user_input
    value += "suffix"
    return eval(value)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 4)])

    def test_union_after_possible_unknown_rebind_keeps_original_alias_taint(self):
        content = '''def handle(user_input, enabled):
    box = {}
    alias = box
    if enabled:
        alias = external_object()
    alias |= {"command": user_input}
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 7)])

    def test_maybe_rebound_receiver_cannot_assume_setitem_returns_none(self):
        content = '''def handle(user_input, enabled):
    box = {}
    if enabled:
        box = external_object()
    return eval(box.__setitem__("command", user_input))
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_maybe_rebound_receiver_cannot_assume_update_returns_none(self):
        content = '''def handle(user_input, enabled):
    box = {}
    if enabled:
        box = external_object()
    return eval(box.update(command=user_input))
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_maybe_rebound_update_receiver_keeps_original_alias_mutation(self):
        content = '''def handle(user_input, enabled):
    box = {}
    alias = box
    if enabled:
        alias = external_object()
    alias.update(command=user_input)
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 7)])

    def test_maybe_rebound_receiver_cannot_clear_original_alias(self):
        content = '''def handle(user_input, enabled):
    box = {"command": user_input}
    alias = box
    if enabled:
        alias = external_object()
    alias.update(command="1+1")
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 7)])

    def test_setdefault_after_possible_unknown_rebind_keeps_shared_write(self):
        content = '''def handle(user_input, enabled):
    box = {}
    alias = box
    if enabled:
        alias = external_object()
    alias.setdefault("command", user_input)
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 7)])

    def test_setitem_call_mutates_shared_alias_and_returns_none(self):
        content = '''def handle(user_input):
    box = {}
    alias = box
    result = alias.__setitem__("command", user_input)
    eval(result)
    eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 6)])

    def test_setitem_exact_overwrite_keeps_safe_sibling_precise(self):
        content = '''def handle(user_input):
    box = {"command": user_input}
    box.__setitem__("command", "1+1")
    box.__setitem__("dangerous", user_input)
    eval(box["command"])
    eval(box["dangerous"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 6)])

    def test_setitem_unknown_key_stays_conservative(self):
        content = '''def handle(user_input, key):
    box = {"command": "1+1"}
    box.__setitem__(key, user_input)
    return eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 4)])

    def test_update_preserves_untrusted_key_provenance(self):
        content = '''def handle(user_input):
    box = {}
    box.update({user_input: "1+1"})
    key = next(iter(box))
    return eval(key)
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_update_evaluates_keywords_before_applying_field_writes(self):
        content = '''def handle(user_input):
    box = {"command": user_input}
    box.update({"command": "1+1"}, captured=box["command"])
    eval(box["command"])
    eval(box["captured"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_union_evaluates_all_values_before_mutating_receiver(self):
        content = '''def handle(user_input):
    box = {"command": "1+1"}
    box |= {"command": user_input, "captured": box["command"]}
    eval(box["captured"])
    eval(box["command"])
'''
        self.assertEqual(self.flow_lines(content), [("FLOW001", 5)])

    def test_update_return_is_not_the_tainted_dictionary(self):
        content = '''def handle(user_input):
    box = {}
    result = box.update(command=user_input)
    return eval(result)
'''
        self.assertEqual(self.flow_lines(content), [])


if __name__ == "__main__":
    unittest.main()
