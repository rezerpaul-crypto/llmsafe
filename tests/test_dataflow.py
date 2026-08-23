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
