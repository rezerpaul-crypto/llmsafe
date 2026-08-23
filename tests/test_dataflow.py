import unittest
from pathlib import Path

from llmsafe.rules.agents import AgentToolRule
from llmsafe.rules.dataflow import DataflowRule


def findings_for(rule, content):
    return list(rule.scan(Path("agent.py"), content))


class DataflowRuleTests(unittest.TestCase):
    def test_traces_model_sdk_response_to_eval(self):
        content = """
def run(client, user_input):
    response = client.responses.create(input=user_input)
    generated_code = response.output_text
    return eval(generated_code)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertIn("model", findings[0].message)
        self.assertGreaterEqual(len(findings[0].evidence), 2)
        self.assertEqual(findings[0].evidence[-1].message, "reaches eval")

    def test_traces_user_input_through_interpolation_to_shell(self):
        content = """
import subprocess

def run(user_input):
    command = f"tool --task {user_input}"
    subprocess.run(command, shell=True)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_traces_request_data_to_http_client(self):
        content = """
import requests

def fetch():
    target = request.args["url"]
    return requests.get(target)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW004"])

    def test_traces_dynamic_sql_and_tool_dispatch(self):
        content = """
def lookup(user_query, model_output, cursor, tools):
    statement = f"SELECT * FROM docs WHERE name = '{user_query}'"
    cursor.execute(statement)
    return tools[model_output]()
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"FLOW003", "FLOW005"},
        )

    def test_merges_taint_across_branches(self):
        content = """
def run(user_input, enabled):
    command = "safe"
    if enabled:
        command = user_input
    os.system(command)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_does_not_flag_constant_operations(self):
        content = """
import requests
import subprocess

subprocess.run(["git", "status"], check=True)
requests.get("https://example.com/health")
cursor.execute("SELECT id FROM docs WHERE id = ?", [document_id])
tools["search"]()
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_traces_user_input_through_local_helper(self):
        content = """
def execute(value):
    return eval(value)

def run(user_input):
    return execute(user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertEqual(findings[0].line, 6)
        self.assertIn("execute() -> eval", findings[0].message)
        self.assertIn("local helper reaches eval", [item.message for item in findings[0].evidence])

    def test_builds_transitive_summaries_and_maps_keyword_arguments(self):
        content = """
import requests

def fetch(value):
    return requests.get(value)

def load(target):
    return fetch(target)

def run(model_output):
    return load(target=model_output)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW004"])
        self.assertIn("load() -> requests.get", findings[0].message)

    def test_local_summary_tracks_only_sink_relevant_parameters(self):
        content = """
def execute(statement, parameters):
    return cursor.execute(statement, parameters)

def safe(user_input):
    return execute("SELECT value FROM docs WHERE id = ?", [user_input])

def unsafe(user_input):
    return execute(user_input, [])
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW003"])
        self.assertEqual(findings[0].line, 9)

    def test_constant_local_helper_call_is_not_reported(self):
        content = """
def execute(value):
    return os.system(value)

execute("fixed-command")
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_maps_keyword_only_and_variadic_parameters(self):
        content = """
def evaluate(*, expression):
    return eval(expression)

def execute(*values):
    return os.system(values[0])

def run(user_input):
    evaluate(expression=user_input)
    execute("prefix", user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["FLOW001", "FLOW002"],
        )

    def test_maps_unpacked_keyword_arguments(self):
        content = """
def evaluate(**values):
    return eval(values["expression"])

def run(user_input):
    return evaluate(**user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_transitive_summary_preserves_parameters_for_repeated_sink_rule(self):
        content = """
def inner(left, right):
    eval(left)
    eval(right)

def outer(first, second):
    inner(first, second)

def run(user_input):
    outer("fixed", user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_resolves_long_reverse_ordered_helper_chain(self):
        functions = [
            f"def helper_{index}(value):\n    return helper_{index - 1}(value)\n"
            for index in range(24, 0, -1)
        ]
        functions.append("def helper_0(value):\n    return eval(value)\n")
        functions.append("def run(user_input):\n    return helper_24(user_input)\n")

        findings = findings_for(DataflowRule(), "\n".join(functions))

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])


class AgentToolRuleTests(unittest.TestCase):
    def test_detects_dangerous_tool_through_import_alias(self):
        content = """
from langchain_experimental.tools import PythonREPLTool as PythonTool

tool = PythonTool()
"""
        findings = findings_for(AgentToolRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["AGENT001"])

    def test_detects_dangerous_flags_and_disabled_approval(self):
        content = """
create_agent(tools=tools, allow_dangerous_code=True)
ToolRunner(tools=tools, require_approval=False)
"""
        findings = findings_for(AgentToolRule(), content)
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"AGENT002", "AGENT003"},
        )

    def test_allows_approval_and_safe_tools(self):
        content = """
SearchTool()
ToolRunner(tools=tools, require_approval=True)
"""
        self.assertEqual(findings_for(AgentToolRule(), content), [])


if __name__ == "__main__":
    unittest.main()
