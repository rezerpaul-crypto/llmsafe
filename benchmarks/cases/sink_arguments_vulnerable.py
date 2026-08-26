"""Untrusted values bind to sensitive parameters through supported call signatures."""

import subprocess

import httpx
import requests


def run(model_output, user_input, cursor):
    subprocess.run(args=model_output, check=True)
    cursor.execute(operation=user_input)
    requests.request("GET", model_output)
    return httpx.stream("GET", url=model_output)
