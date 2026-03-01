from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Base class for all website health scanners."""

    def __init__(self, name, display_name, is_fast=True):
        self.name = name
        self.display_name = display_name
        self.is_fast = is_fast

    @abstractmethod
    def run(self, target_url, **kwargs):
        """Execute the scan and return a report dictionary."""
        pass

class ScannerRegistry:
    """Manages the registration and execution of scanner plugins."""

    def __init__(self):
        self._scanners = []

    def register(self, scanner):
        """Register a new scanner plugin."""
        if not isinstance(scanner, BaseScanner):
            raise TypeError("Only instances of BaseScanner can be registered.")
        self._scanners.append(scanner)

    def get_scanners(self, fast_only=False):
        """Return a list of registered scanners."""
        if fast_only:
            return [s for s in self._scanners if s.is_fast]
        return self._scanners

# Global registry instance
registry = ScannerRegistry()
