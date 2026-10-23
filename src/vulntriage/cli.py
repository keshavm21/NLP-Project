"""Single entry point behind the Makefile: `python -m vulntriage.cli <command>`.

Each command points to a `main()` function in some module. Owners create that module
when they implement the step; until then the command prints who owns it.
Run `python -m vulntriage.cli status` to see what is implemented.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys

# command -> (module with a main(argv) function, owner, what it does)
COMMANDS: dict[str, tuple[str, str, str]] = {
    "data": ("vulntriage.ingest.download", "P1", "download all sources into data/raw/"),
    "benchmark": ("vulntriage.ingest.benchmark", "P1", "build splits + silver labels"),
    "train-extract": ("vulntriage.extract.train", "P2", "train the span tagger"),
    "eval-extract": ("vulntriage.extract.evaluate", "P2", "evaluate extractors"),
    "train-link": ("vulntriage.linking.train", "P3", "build index + train linker"),
    "eval-link": ("vulntriage.linking.evaluate", "P3", "evaluate linkers"),
    "train-cwe": ("vulntriage.classify.train_cwe", "P4", "train CWE classifier"),
    "eval-cwe": ("vulntriage.classify.evaluate_cwe", "P4", "evaluate CWE"),
    "train-cvss": ("vulntriage.classify.train_cvss", "P4", "train CVSS model"),
    "eval-cvss": ("vulntriage.classify.evaluate_cvss", "P4", "evaluate CVSS"),
    "train-exploit": ("vulntriage.classify.train_exploit", "P4", "train exploitation classifier"),
    "eval-exploit": ("vulntriage.classify.evaluate_exploit", "P4", "evaluate exploitation"),
    "eval-rank": ("vulntriage.rank.evaluate", "P5", "evaluate ranking"),
    "eval-e2e": ("vulntriage.eval.replay", "P5", "end-to-end replay over the test window"),
    "serve": ("vulntriage.api.app", "P5", "run API + dashboard"),
}


def _module_exists(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def status() -> int:
    width = max(map(len, COMMANDS))
    for cmd, (module, owner, desc) in COMMANDS.items():
        mark = "done" if _module_exists(module) else "todo"
        print(f"[{mark}] {cmd:<{width}}  {owner}  {desc}  ({module})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulntriage")
    parser.add_argument("command", choices=[*COMMANDS, "status"])
    parser.add_argument("args", nargs=argparse.REMAINDER, help="passed to the command")
    ns = parser.parse_args(argv)

    if ns.command == "status":
        return status()

    module, owner, desc = COMMANDS[ns.command]
    if not _module_exists(module):
        print(
            f"'{ns.command}' ({desc}) is not implemented yet.\n"
            f"Owner: {owner}. Create {module.replace('.', '/')}.py with a main(argv) function.",
            file=sys.stderr,
        )
        return 2
    return int(importlib.import_module(module).main(ns.args) or 0)


if __name__ == "__main__":
    sys.exit(main())
