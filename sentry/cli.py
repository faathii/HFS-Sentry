"""Main Command Line Interface for HFS-Sentry."""

import argparse
import sys
from typing import List, Optional

from sentry import __version__
from sentry.core.colors import bold, cyan, green, yellow, dim
from sentry.core.registry import get_tool_registry, list_tools


BANNER = rf"""{cyan(bold(r"""
  _    _ ______ _____        _____            _              
 | |  | |  ____/ ____|      / ____|          | |             
 | |__| | |__ | (___ ______| (___   ___ _ __ | |_ _ __ _   _ 
 |  __  |  __| \___ \______| \___ \ / _ \ '_ \| __| '__| | | |
 | |  | | |    ____) |      ____) |  __/ | | | |_| |  | |_| |
 |_|  |_|_|   |_____/      |_____/ \___|_| |_|\__|_|   \__, |
                                                        __/ |
                                                       |___/ 
"""))}
  {dim("High-Density Cybersecurity & Diagnostic Suite | Standard Python 3")}
  {dim("Version:")} {green(__version__)}  {dim("Author:")} {yellow("Hamza El Fathi Sofyani")}
  {dim("Repo:")} {cyan("https://github.com/faathii/HFS-Sentry")}
"""


def _ensure_tools_loaded() -> None:
    """Import tools package to trigger dynamic registration."""
    import sentry.tools  # noqa: F401


def build_parser() -> argparse.ArgumentParser:
    """Construct top-level argument parser and dynamic subparsers for each registered tool."""
    _ensure_tools_loaded()

    parser = argparse.ArgumentParser(
        prog="hfs-sentry",
        description="HFS-Sentry: Modular, zero-dependency cybersecurity toolkit.",
        epilog="Use 'hfs-sentry <tool> --help' for options specific to any tool.",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"HFS-Sentry v{__version__}",
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all registered tools and technical modules.",
    )

    subparsers = parser.add_subparsers(
        dest="tool_name",
        title="Available Tools",
        description="Run any tool by specifying its name:",
        metavar="<tool>",
    )

    for tool in list_tools():
        tool_subparser = subparsers.add_parser(
            tool.name,
            help=f"[{tool.category}] {tool.description}",
            description=f"{tool.name.upper()} - {tool.description}\nAuthor: {tool.author} (v{tool.version})",
        )
        tool.register_arguments(tool_subparser)

    return parser


def print_tool_catalogue() -> None:
    """Print an aesthetic table of all registered tools."""
    tools = list_tools()
    print("\n" + "=" * 78)
    print(f" {bold('HFS-Sentry Registered Tools Directory')} ({len(tools)} tools available)")
    print("=" * 78)
    print(f" {'NAME':<16} {'CATEGORY':<14} {'VER':<8} {'DESCRIPTION'}")
    print(" " + "-" * 76)
    for t in tools:
        print(f" {green(t.name):<25} {cyan(t.category):<23} {t.version:<8} {t.description}")
    print("=" * 78)
    print(f"\n Run any tool using: {bold('python sentry.py <tool> --help')}\n")


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for CLI execution."""
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    # If no arguments provided, show banner and available tools
    if not argv:
        print(BANNER)
        print_tool_catalogue()
        return 0

    # If --list is requested
    if "-l" in argv or "--list" in argv:
        print(BANNER)
        print_tool_catalogue()
        return 0

    args = parser.parse_args(argv)

    if not args.tool_name:
        parser.print_help()
        return 0

    registry = get_tool_registry()
    tool = registry.get(args.tool_name)
    if not tool:
        print(f"[!] Error: Tool '{args.tool_name}' not found.", file=sys.stderr)
        return 1

    try:
        return tool.run(args)
    except KeyboardInterrupt:
        print(f"\n[!] Tool '{args.tool_name}' interrupted by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[!] Tool '{args.tool_name}' failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
