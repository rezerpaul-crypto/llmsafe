"""Parameter-shadowed import names are not treated as known security APIs."""

from subprocess import run as launch

import requests as http

IMPORTED_HTTP_CLIENT = http
IMPORTED_PROCESS_RUNNER = launch


def run(user_input, http, launch):
    http.get(user_input)
    return launch(user_input)
