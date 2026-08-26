"""Tainted ancillary options do not replace explicitly safe sink parameters."""

import subprocess

import httpx
import requests


def run(user_input, cursor):
    subprocess.run(
        ["git", "status", "--short"],
        check=True,
        env={"LLMSAFE_TASK": user_input},
    )
    cursor.execute("SELECT value FROM docs WHERE id = ?", parameters=[user_input])
    requests.request(
        "GET",
        "https://example.com/search",
        params={"query": user_input},
    )
    return httpx.stream(user_input, "https://example.com/events")
