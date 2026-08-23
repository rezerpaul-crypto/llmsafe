"""Allow ``python -m llmsafe`` to behave like the command-line tool."""

from llmsafe.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
