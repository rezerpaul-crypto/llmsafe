import sys
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

    def test_traces_openai_agents_runner_result_to_process(self):
        content = """
import subprocess
from agents import Runner

async def run(agent):
    result = await Runner.run(agent, "inspect the repository")
    subprocess.run(result.final_output, shell=True)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])
        self.assertIn("model", findings[0].message)

    def test_treats_openai_function_tool_parameters_as_model_input(self):
        content = """
from agents import function_tool

@function_tool
def calculate(expression: str):
    return eval(expression)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertIn(
            "OpenAI function tool parameter: expression",
            findings[0].evidence[0].message,
        )

    def test_supports_openai_tool_alias_and_excludes_sdk_context(self):
        content = """
import requests
from agents import RunContextWrapper
from agents.decorators import tool as register_tool
from agents.tool_context import ToolContext

@register_tool(name_override="fetch")
def fetch(context: RunContextWrapper[dict], target: str):
    eval(context)
    return requests.get(target)

@register_tool
def inspect(context: ToolContext[dict]):
    return eval(context)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW004"])
        self.assertIn(
            "OpenAI function tool parameter: target",
            findings[0].evidence[0].message,
        )

    def test_supports_openai_agents_module_alias(self):
        content = """
import subprocess
import agents as sdk

@sdk.function_tool()
def launch(script: str):
    return subprocess.run(script)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_does_not_trust_similarly_named_or_rebound_openai_decorators(self):
        content = """
from application import function_tool
from agents import function_tool as official_tool

official_tool = local_decorator

@function_tool
def one(expression):
    return eval(expression)

@official_tool
def two(script):
    return eval(script)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_langchain_tool_input_is_model_source_g01(self):
        content = """
from langchain.tools import tool
@tool
def calculate(expression: str) -> str:
    return str(eval(expression))
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertTrue(any("LangChain" in step.message for step in findings[0].evidence))

    def test_langchain_alias_named_and_async_tool(self):
        content = """
from langchain.tools import tool as register
@register("execute")
async def calculate(expression: str):
    return eval(expression)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW001"],
        )

    def test_langchain_injected_toolruntime_not_model_source_c01(self):
        content = """
from langchain.tools import tool, ToolRuntime
@tool
def configured(runtime: ToolRuntime):
    return eval(runtime.context.expression)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_langchain_rebound_or_fake_decorator_not_trusted(self):
        content = """
from langchain.tools import tool
from unrelated import tool as other
tool = other
@tool
def evaluate(expression):
    return eval(expression)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_pydantic_tool_plain_is_model_source_g02(self):
        content = """
from pydantic_ai import Agent
agent = Agent()
@agent.tool_plain
def calculate(expression: str):
    return eval(expression)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertTrue(any("PydanticAI" in step.message for step in findings[0].evidence))

    def test_pydantic_agent_alias_and_async_tool(self):
        content = """
import pydantic_ai as ai
owner = ai.Agent()
agent = owner
@agent.tool
async def calculate(expression: str):
    return eval(expression)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW001"],
        )

    def test_pydantic_runcontext_not_model_source_c02(self):
        content = """
from pydantic_ai import Agent, RunContext
agent = Agent()
@agent.tool
def configured(ctx: RunContext[str]):
    return eval(ctx.deps)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_pydantic_rebound_agent_and_fake_method_are_not_tool_boundary(self):
        content = """
from pydantic_ai import Agent
from unrelated import make_agent
agent = Agent()
agent = make_agent()
@agent.tool_plain
def calculate(expression):
    return eval(expression)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_pydantic_non_agent_tool_plain_is_not_model_source(self):
        content = """
from unrelated import Agent
agent = Agent()
@agent.tool_plain
def calculate(expression):
    return eval(expression)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_traces_user_input_through_interpolation_to_shell(self):
        content = """
import subprocess

def run(user_input):
    command = f"tool --task {user_input}"
    subprocess.run(command, shell=True)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_treats_mcpserver_tool_parameters_as_remote_input(self):
        content = """
from mcp.server import MCPServer

server = MCPServer("Execution tools")

@server.tool()
def calculate(expression: str):
    return eval(expression)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])
        self.assertIn("MCP tool parameter: expression", findings[0].evidence[0].message)

    def test_supports_legacy_fastmcp_constructor_alias(self):
        content = """
import subprocess
from mcp.server.fastmcp import FastMCP as Server

tools = Server("Execution tools")

@tools.tool()
def launch(script: str):
    return subprocess.run(script)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_supports_module_alias_and_bare_tool_decorator(self):
        content = """
import requests
import mcp.server as sdk

service = sdk.MCPServer("Fetch tools")

@service.tool
async def fetch(target: str):
    return requests.get(target)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW004"])

    def test_does_not_taint_mcp_injected_parameters(self):
        content = """
from typing import Annotated
from mcp.server import MCPServer
from mcp.server.mcpserver import Context, Resolve

server = MCPServer("Execution tools")

@server.tool()
def inspect(
    user_input: Context,
    payload: Annotated[str, Resolve(load_policy)],
):
    eval(user_input)
    return eval(payload)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_does_not_trust_similarly_named_or_rebound_mcp_builders(self):
        content = """
from application import MCPServer
from mcp.server import MCPServer as OfficialServer

OfficialServer = SafeServer
first = MCPServer("local")
second = OfficialServer("local")

@first.tool()
def one(expression):
    return eval(expression)

@second.tool()
def two(script):
    return eval(script)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_traces_request_data_to_http_client(self):
        content = """
import requests

def fetch():
    target = request.args["url"]
    return requests.get(target)
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW004"])

    def test_resolves_external_module_and_symbol_import_aliases(self):
        content = """
import subprocess as process
from agents import Runner as AgentRunner
from requests import get as fetch

async def run(user_input):
    result = await AgentRunner.run(None, user_input)
    process.run(args=result.final_output)
    return fetch(url=user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["FLOW002", "FLOW004"],
        )
        self.assertIn("model", findings[0].message)
        self.assertEqual(findings[0].evidence[-1].message, "reaches subprocess.run")
        self.assertEqual(findings[1].evidence[-1].message, "reaches requests.get")

    def test_resolves_function_local_import_aliases(self):
        content = """
def run(user_input, model_output):
    import httpx as web
    from subprocess import run as launch

    launch(args=model_output)
    return web.get(url=user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["FLOW002", "FLOW004"],
        )

    def test_import_alias_survives_local_function_summary(self):
        content = """
from os import system as launch

def execute(value):
    return launch(value)

def run(user_input):
    return execute(user_input)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])
        self.assertIn("execute() -> os.system", findings[0].message)

    def test_does_not_resolve_shadowed_import_aliases(self):
        content = """
import requests as http
from subprocess import run as launch

http = SafeClient()

def run(user_input):
    launch = safe_launch
    http.get(user_input)
    launch(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_does_not_resolve_shadowed_canonical_import_names(self):
        content = """
import requests
import subprocess

requests = SafeClient()

def run(user_input, subprocess):
    requests.get(user_input)
    return subprocess.run(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_does_not_resolve_relative_import_as_external_api(self):
        content = """
from .requests import get as fetch

def run(user_input):
    return fetch(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    @unittest.skipUnless(sys.version_info >= (3, 10), "requires pattern matching")
    def test_does_not_resolve_pattern_shadowed_import(self):
        content = """
import requests

def run(user_input, payload):
    match payload:
        case {"client": requests}:
            requests.get(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_does_not_guess_ambiguous_or_similarly_named_imports(self):
        content = """
import requests_wrapper as http

try:
    import requests as optional_client
except ImportError:
    import safe_http as optional_client

def run(user_input):
    http.get(user_input)
    return optional_client.get(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_maps_keyword_and_method_specific_sink_arguments(self):
        content = """
import httpx
import requests
import subprocess

def run(model_output, user_input, cursor):
    subprocess.run(args=model_output)
    cursor.execute(operation=user_input)
    requests.get(url=user_input)
    requests.request("GET", model_output)
    httpx.stream("GET", url=model_output)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["FLOW002", "FLOW003", "FLOW004", "FLOW004", "FLOW004"],
        )

    def test_ignores_tainted_non_sink_arguments(self):
        content = """
import httpx
import requests
import subprocess

def run(user_input, cursor):
    subprocess.run(["fixed-command"], env=user_input)
    cursor.execute("SELECT value FROM docs WHERE id = ?", parameters=[user_input])
    requests.get("https://example.com/search", params={"query": user_input})
    requests.request(user_input, "https://example.com/health")
    httpx.stream(user_input, "https://example.com/events")
    subprocess.run(["fixed-command"], **user_input)
    requests.get("https://example.com/health", **user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_treats_unpacked_keywords_as_sink_input_when_unbound(self):
        content = """
import requests
import subprocess

def run(user_input, model_output):
    subprocess.run(**user_input)
    requests.get(**model_output)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["FLOW002", "FLOW004"],
        )

    def test_keyword_sink_binding_survives_local_function_summary(self):
        content = """
import subprocess

def launch(**options):
    subprocess.run(**options)

def run(model_output):
    launch(args=model_output)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])
        self.assertIn("launch() -> subprocess.run", findings[0].message)

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

    def test_dictionary_field_write_reaches_eval_g07(self):
        content = """
def handle(user_input):
    box = {}
    box["dangerous"] = user_input
    box["safe"] = "1+1"
    return eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_fields_do_not_contaminate_each_other_c03(self):
        content = """
def handle(user_input):
    box = {}
    box["dangerous"] = user_input
    box["safe"] = "1+1"
    return eval(box["safe"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dictionary_literal_fields_remain_separate(self):
        content = """
def handle(user_input):
    box = {"dangerous": user_input, "safe": "1+1"}
    eval(box["safe"])
    eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_aliases_share_mutated_fields(self):
        content = """
def handle(user_input):
    box = {}
    alias = box
    alias["dangerous"] = user_input
    return eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_rebinding_dictionary_does_not_retain_old_alias_fields(self):
        content = """
def handle(user_input):
    box = {}
    old_box = box
    old_box["dangerous"] = user_input
    box = {}
    return eval(box["dangerous"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dictionary_strong_overwrite_removes_stale_taint(self):
        content = """
def handle(user_input):
    box = {}
    box["dangerous"] = user_input
    box["dangerous"] = "1+1"
    return eval(box["dangerous"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_unknown_dictionary_key_read_is_conservative(self):
        content = """
def handle(user_input, field):
    box = {"dangerous": user_input, "safe": "1+1"}
    return eval(box[field])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_unknown_dictionary_key_write_is_conservative(self):
        content = """
def handle(user_input, field):
    box = {}
    box[field] = user_input
    return eval(box["safe"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_conditional_dictionary_field_mutation_remains_visible(self):
        content = """
def handle(user_input, enabled):
    box = {}
    if enabled:
        box["dangerous"] = user_input
    return eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_field_return_is_preserved_in_helper_summary(self):
        content = """
def choose(value):
    box = {}
    box["dangerous"] = value
    return box["dangerous"]

def handle(user_input):
    return eval(choose(user_input))
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_get_reads_selected_field_not_sibling(self):
        content = """
def handle(user_input):
    box = {"dangerous": user_input, "safe": "1+1"}
    eval(box.get("safe"))
    eval(box.get("dangerous"))
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_get_default_remains_conservative(self):
        content = """
def handle(user_input):
    box = {"safe": "1+1"}
    return eval(box.get("missing", user_input))
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_duplicate_dictionary_literal_keys_take_final_value(self):
        content = """
def handle(user_input):
    box = {"command": user_input, "command": "1+1"}
    return eval(box["command"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dictionary_update_literal_fields_keep_precise_taint(self):
        content = """
def handle(user_input):
    box = {}
    box.update({"dangerous": user_input, "safe": "1+1"})
    eval(box["safe"])
    eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_update_keyword_and_alias_mutation(self):
        content = """
def handle(user_input):
    box = {}
    alias = box
    alias.update(dangerous=user_input)
    return eval(box["dangerous"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_update_overwrite_removes_old_field_taint(self):
        content = """
def handle(user_input):
    box = {"dangerous": user_input}
    box.update({"dangerous": "1+1"})
    return eval(box["dangerous"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dictionary_update_unknown_mapping_is_conservative(self):
        content = """
def handle(user_input):
    box = {"safe": "1+1"}
    box.update(user_input)
    return eval(box["safe"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_update_dynamic_key_is_conservative(self):
        content = """
def handle(user_input, key):
    box = {"safe": "1+1"}
    box.update({key: user_input})
    return eval(box["safe"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_setdefault_mutation_reaches_sink(self):
        content = """
def handle(user_input):
    box = {}
    box.setdefault("command", user_input)
    return eval(box["command"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_setdefault_return_reaches_sink(self):
        content = """
def handle(user_input):
    box = {}
    return eval(box.setdefault("command", user_input))
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_dictionary_setdefault_no_untrusted_default_is_quiet(self):
        content = """
def handle(user_input):
    box = {}
    box.setdefault("command", "1+1")
    return eval(box["command"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dictionary_setdefault_dynamic_key_is_conservative(self):
        content = """
def handle(user_input, key):
    box = {"command": "1+1"}
    box.setdefault(key, user_input)
    return eval(box["command"])
"""
        findings = findings_for(DataflowRule(), content)
        self.assertEqual([finding.rule_id for finding in findings], ["FLOW001"])

    def test_nested_dictionary_field_taint_reaches_code_sink(self):
        content = """
def handle(user_input):
    box = {"inner": {"safe": "1+1"}}
    box["inner"]["dangerous"] = user_input
    return eval(box["inner"]["dangerous"])
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_nested_dictionary_sibling_remains_safe(self):
        content = """
def handle(user_input):
    box = {"inner": {"safe": "1+1", "dangerous": user_input}}
    return eval(box["inner"]["safe"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_nested_dictionary_alias_mutation_is_visible(self):
        content = """
def handle(user_input):
    box = {"inner": {}}
    inner = box["inner"]
    inner["dangerous"] = user_input
    return eval(box["inner"]["dangerous"])
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_nested_dictionary_replacement_kills_old_field(self):
        content = """
def handle(user_input):
    box = {"inner": {"dangerous": user_input}}
    box["inner"] = {"dangerous": "1+1"}
    return eval(box["inner"]["dangerous"])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_simple_namespace_attribute_taint_is_precise(self):
        content = """
from types import SimpleNamespace
def handle(user_input):
    state = SimpleNamespace(safe="1+1", dangerous=user_input)
    eval(state.safe)
    eval(state.dangerous)
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_simple_namespace_alias_attribute_mutation(self):
        content = """
import types
def handle(user_input):
    state = types.SimpleNamespace(safe="1+1")
    alias = state
    alias.dangerous = user_input
    return eval(state.dangerous)
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_simple_namespace_attribute_sibling_remains_safe(self):
        content = """
from types import SimpleNamespace
def handle(user_input):
    state = SimpleNamespace(safe="1+1")
    state.dangerous = user_input
    return eval(state.safe)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_unknown_outer_key_mutation_reaches_known_nested_read(self):
        content = """
def handle(user_input, unknown_key):
    box = {"inner": {"safe": "1+1"}}
    box[unknown_key]["dangerous"] = user_input
    return eval(box["inner"]["dangerous"])
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_simple_namespace_get_callable_is_not_dict_get(self):
        content = """
from types import SimpleNamespace
def handle(user_input):
    state = SimpleNamespace(get=lambda name: user_input)
    return eval(state.get("missing"))
"""
        self.assertEqual(
            [f.rule_id for f in findings_for(DataflowRule(), content)], ["FLOW001"]
        )

    def test_echo_data_argument_does_not_control_shell_g04(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/bin/echo", user_input], check=True, shell=False)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_echo_data_argument_without_shell_flag_is_quiet(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.check_output(["/usr/bin/echo", user_input])
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_dynamic_program_selection_remains_reported(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run([user_input, "safe"], shell=False)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_shell_true_never_gets_echo_data_only_exemption(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/bin/echo", user_input], shell=True)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_unknown_shell_flag_blocks_echo_exemption(self):
        content = """
import subprocess
def handle(user_input, use_shell):
    return subprocess.run(["/bin/echo", user_input], shell=use_shell)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_fixed_interpreter_with_untrusted_code_is_reported(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/usr/bin/python3", "-c", user_input], shell=False)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_fixed_unknown_executable_with_untrusted_argument_is_reported(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/usr/bin/git", user_input], shell=False)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_changed_executable_never_gets_echo_exemption(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/bin/echo", "safe"], executable=user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_dynamic_kwargs_never_get_echo_exemption(self):
        content = """
import subprocess
def handle(user_input):
    return subprocess.run(["/bin/echo", user_input], **{"shell": False})
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_local_instance_method_reports_shell_sink_g03(self):
        content = """
import os
class Executor:
    def execute(self, value):
        return os.system(value)
def handle(user_input):
    worker = Executor()
    return worker.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_local_instance_method_alias_reports_shell_sink(self):
        content = """
import os
class Executor:
    def execute(self, value):
        return os.system(value)
def handle(user_input):
    worker = Executor()
    alias = worker
    return alias.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW002"],
        )

    def test_local_class_not_instantiated_does_not_disguise_unknown_cursor(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    return cursor.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_known_benign_execute_is_not_sql_g08(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    recorder = Recorder()
    return recorder.execute(user_input)
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_known_local_execute_that_reaches_database_still_reports_sql(self):
        content = """
class DatabaseAdapter:
    def execute(self, value):
        return cursor.execute(value)
def handle(user_input):
    adapter = DatabaseAdapter()
    return adapter.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_rebound_benign_receiver_does_not_hide_sql_sink(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    recorder = Recorder()
    recorder = get_cursor()
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_instance_execute_monkeypatch_does_not_hide_sql(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    recorder = Recorder()
    recorder.execute = cursor.execute
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_instance_method_alias_monkeypatch_does_not_hide_sql(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    recorder = Recorder()
    alias = recorder
    alias.execute = cursor.execute
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_maybe_monkeypatched_method_in_branch_is_not_trusted(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input, enabled):
    recorder = Recorder()
    if enabled:
        recorder.execute = cursor.execute
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_setattr_invalidates_local_method_identity(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
def handle(user_input):
    recorder = Recorder()
    setattr(recorder, "execute", cursor.execute)
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_class_level_replacement_disables_local_method_suppression(self):
        content = """
class Recorder:
    def execute(self, value):
        return value
Recorder.execute = cursor.execute
def handle(user_input):
    recorder = Recorder()
    return recorder.execute(user_input)
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW003"],
        )

    def test_closed_constant_only_dispatch_is_not_dangerous_g05(self):
        content = """
def status():
    return "ok"
def help_text():
    return "help"
OPS = {"status": status, "help": help_text}
def handle(user_input):
    return OPS[user_input]()
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_mutable_closed_dispatch_still_reports(self):
        content = """
def status():
    return "ok"
OPS = {"status": status}
OPS["unsafe"] = dynamic_tool
def handle(user_input):
    return OPS[user_input]()
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW005"],
        )

    def test_unknown_registered_function_still_reports_dynamic_dispatch(self):
        content = """
def status():
    return "ok"
OPS = {"status": status, "run": os.system}
def handle(user_input):
    return OPS[user_input]()
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW005"],
        )

    def test_non_constant_safe_function_body_stays_conservative(self):
        content = """
def status():
    return external_status()
OPS = {"status": status}
def handle(user_input):
    return OPS[user_input]()
"""
        self.assertEqual(
            [item.rule_id for item in findings_for(DataflowRule(), content)],
            ["FLOW005"],
        )

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

    def test_constant_helper_return_does_not_propagate_argument_taint(self):
        content = """
import os

def fixed_command(user_input):
    return "printf safe"

def run(user_input):
    return os.system(fixed_command(user_input))
"""
        self.assertEqual(findings_for(DataflowRule(), content), [])

    def test_helper_return_tracks_only_relevant_parameters(self):
        content = """
import os

def select_command(command, audit_context):
    return command

def safe(user_input):
    return os.system(select_command("printf safe", user_input))

def unsafe(user_input):
    return os.system(select_command(user_input, "fixed context"))
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])
        self.assertEqual(findings[0].line, 11)

    def test_transitive_helper_return_summary_reaches_sink(self):
        content = """
import os

def normalize(value):
    return value.strip()

def command_for(value):
    return normalize(value)

def run(user_input):
    return os.system(command_for(user_input))
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])

    def test_helper_return_preserves_intrinsic_model_source(self):
        content = """
import os

def generate(client):
    return client.responses.create(input="fixed prompt")

def run(client):
    return os.system(generate(client).output_text)
"""
        findings = findings_for(DataflowRule(), content)

        self.assertEqual([finding.rule_id for finding in findings], ["FLOW002"])
        self.assertIn("model", findings[0].message)

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
