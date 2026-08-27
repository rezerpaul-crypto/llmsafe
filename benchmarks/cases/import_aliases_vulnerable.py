"""Imported security APIs retain their meaning when renamed locally."""

import subprocess as process

from agents import Runner as AgentRunner
from requests import get as fetch


async def run(user_input):
    result = await AgentRunner.run(None, user_input)
    process.run(args=result.final_output)
    return fetch(url=user_input)
