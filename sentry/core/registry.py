"""Dynamic tool registry for HFS-Sentry."""

from typing import Dict, List, Optional, Type
from sentry.core.base import BaseTool

_REGISTRY: Dict[str, BaseTool] = {}


def register_tool(tool_cls: Type[BaseTool]) -> Type[BaseTool]:
    """Decorator to register a tool class into the HFS-Sentry registry."""
    instance = tool_cls()
    name = instance.name.lower().strip()
    if name in _REGISTRY:
        raise ValueError(f"Tool with name '{name}' is already registered in HFS-Sentry.")
    _REGISTRY[name] = instance
    return tool_cls


def get_tool(name: str) -> Optional[BaseTool]:
    """Retrieve a registered tool by its identifier."""
    return _REGISTRY.get(name.lower().strip())


def get_tool_registry() -> Dict[str, BaseTool]:
    """Return all currently registered tools."""
    return _REGISTRY


def list_tools() -> List[BaseTool]:
    """Return list of all registered tools sorted by name."""
    return sorted(_REGISTRY.values(), key=lambda t: t.name)

