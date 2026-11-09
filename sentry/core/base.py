"""Base class definition for all HFS-Sentry tools."""

from abc import ABC, abstractmethod
import argparse
from typing import Optional


class BaseTool(ABC):
    """Abstract base class that every HFS-Sentry tool must inherit from."""

    name: str = "unnamed-tool"
    description: str = "No description provided."
    author: str = "Hamza El Fathi Sofyani"
    version: str = "1.0.0"
    category: str = "General"

    @abstractmethod
    def register_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register tool-specific CLI arguments onto the subparser."""
        pass

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        """Execute the tool logic with parsed arguments. Returns status code (0 = success)."""
        pass

    def get_info(self) -> dict:
        """Return metadata summary for this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "category": self.category,
        }

