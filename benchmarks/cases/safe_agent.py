"""Equivalent agent boundaries designed to remain free of LLMSafe findings."""

import subprocess

ALLOWED_TOPICS = {"security", "python"}


def search(topic: str, cursor):
    if topic not in ALLOWED_TOPICS:
        raise ValueError("Unsupported topic")
    cursor.execute("SELECT * FROM memory WHERE topic = ?", [topic])
    return subprocess.run(["agent-tool", "--topic", topic], check=True)


def dispatch_search():
    tools = {"search": search}
    return tools["search"]
