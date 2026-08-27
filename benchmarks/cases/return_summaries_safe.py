"""Safe fixed values returned by helpers that receive untrusted context."""

import subprocess

import requests


def fixed_command(untrusted_context):
    return ["tool", "status"]


def fixed_url(untrusted_context):
    return "https://api.example.org/health"


def run(user_input):
    subprocess.run(fixed_command(user_input), check=True)
    return requests.get(fixed_url(user_input))
