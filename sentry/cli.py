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
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Launch interactive security menu mode.",
    )
    parser.add_argument(
        "-g", "--gui",
        action="store_true",
        help="Launch the HFS-Sentry Desktop Suite Hub (GUI).",
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


def run_interactive_menu(parser: argparse.ArgumentParser) -> int:
    """Run an interactive prompt menu to easily invoke any tool."""
    print(BANNER)
    tools = list_tools()
    while True:
        print("\n" + "=" * 60)
        print(f" {bold('HFS-Sentry Interactive Console')}")
        print("=" * 60)
        for idx, t in enumerate(tools, 1):
            print(f"  [{cyan(str(idx))}] {bold(t.name):<18} ({t.category}) - {t.description}")
        print(f"  [{yellow('0')}] Exit Console")
        print("=" * 60)

        try:
            choice = input(f"\nSelect a tool [0-{len(tools)}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return 0

        if choice in ("0", "q", "exit"):
            print("Session ended.")
            return 0

        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(tools):
            print(red("[!] Invalid option. Please choose a valid tool number."))
            continue

        selected_tool = tools[int(choice) - 1]
        print(f"\n---> {bold(selected_tool.name.upper())} ({selected_tool.description})")
        print(f"Enter arguments for {bold(selected_tool.name)} (or press Enter for --help):")
        try:
            user_args = input(f"{selected_tool.name} > ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        cmd_argv = [selected_tool.name]
        if user_args:
            cmd_argv.extend(user_args.split())
        else:
            cmd_argv.append("--help")

        try:
            parsed = parser.parse_args(cmd_argv)
            selected_tool.run(parsed)
        except SystemExit:
            pass
        except Exception as e:
            print(red(f"[!] Error: {e}"))


def launch_gui_hub() -> int:
    """Launch the main HFS-Sentry Desktop Suite Hub."""
    try:
        from sentry.ui.app import SentrySuiteApp
        app = SentrySuiteApp()
        app.mainloop()
        return 0
    except Exception as e:
        print(f"[!] No se pudo iniciar la interfaz gráfica (GUI): {e}", file=sys.stderr)
        return 1


def launch_tool_gui(tool_id: str) -> int:
    """Launch an individual tool in its dedicated independent desktop window."""
    try:
        import tkinter as tk
        from sentry.ui.theme import apply_suite_theme
        from sentry.ui.windows import TOOL_WINDOW_MAP

        window_cls = TOOL_WINDOW_MAP.get(tool_id)
        if not window_cls:
            print(f"[!] No se encontró ventana gráfica para '{tool_id}'", file=sys.stderr)
            return 1

        root = tk.Tk()
        root.withdraw()  # Hide root shell
        apply_suite_theme(root)

        win = window_cls(master=root)
        win.protocol("WM_DELETE_WINDOW", lambda: (win.destroy(), root.quit()))
        root.mainloop()
        return 0
    except Exception as e:
        print(f"[!] Falló el inicio de la ventana para '{tool_id}': {e}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for CLI & GUI execution."""
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    # If --gui or -g requested at top level
    if "-g" in argv or "--gui" in argv:
        return launch_gui_hub()

    # If --interactive is requested
    if "-i" in argv or "--interactive" in argv:
        return run_interactive_menu(parser)

    # If no arguments provided
    if not argv:
        # If in a graphical desktop environment (Windows or X11/Wayland), default to launching the Desktop Suite Hub!
        is_graphical = sys.platform == "win32" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if is_graphical:
            return launch_gui_hub()
        else:
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

    # If --gui was passed to a specific tool (e.g. sentry netsentry --gui)
    if "--gui" in argv or "-g" in argv:
        return launch_tool_gui(args.tool_name)

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

