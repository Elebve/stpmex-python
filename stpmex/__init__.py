__all__ = ['__version__', 'Client']

from .banks import sync_clabe_catalog
from .client import Client
from .version import __version__

sync_clabe_catalog()
