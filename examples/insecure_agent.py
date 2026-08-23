"""Intentionally vulnerable examples for trying LLMSafe. Do not copy into production."""

import subprocess


def run_model_tool(model_command: str, user_input: str) -> None:
    system_prompt = f"You are an admin agent. Follow this user request: {user_input}"
    print(system_prompt)
    subprocess.run(model_command, shell=True)


def evaluate_model_answer(model_answer: str):
    return eval(model_answer)
