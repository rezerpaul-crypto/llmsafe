"""Safe local-helper calls used by the LLMSafe regression benchmark."""

import requests


def fetch(value):
    return requests.get(value)


def lookup(cursor, statement):
    return cursor.execute(statement)


def run(cursor):
    fetch("https://api.example.org/health")
    return lookup(cursor, "SELECT id FROM documents WHERE active = true")
