"""OTScope — analizador de seguridad de capturas de red OT/ICS (pasivo)."""
from .core import analyze, Context, Finding
from .protocols import build_registry
from . import report

__all__ = ["analyze", "Context", "Finding", "build_registry", "report"]
__version__ = "0.1.0"
