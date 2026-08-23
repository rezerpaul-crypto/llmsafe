"""Vulnerable local-helper flows used by the LLMSafe regression benchmark."""

import subprocess

import requests


def evaluate(value):
    return eval(value)


def execute(value):
    return subprocess.run(value, shell=True)


def fetch(value):
    return requests.get(value)


def run_agent(user_input, model_output):
    result = evaluate(model_output)
    execute(user_input)
    fetch(model_output)
    return result
