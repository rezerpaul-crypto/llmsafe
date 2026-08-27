"""Vulnerable flows through local helper return values."""

import subprocess

import requests


def choose(value, audit_context):
    return value


def normalize(value):
    return value.strip()


def run(user_input, model_output):
    subprocess.run(choose(user_input, "fixed audit context"), check=True)
    return requests.get(normalize(model_output))
