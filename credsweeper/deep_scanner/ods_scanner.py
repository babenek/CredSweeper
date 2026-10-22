import logging
from abc import ABC

from credsweeper.deep_scanner.pandas_scanner import PandasScanner

logger = logging.getLogger(__name__)


class OdsScanner(PandasScanner, ABC):
    """Implements xlsx scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Assume, ZIP prefix was checked before"""
        if b"META-INF/manifest.xml" in data and b"mimetype" in data:
            # may be any OpenOffice document, but zip extraction is skipped here
            return True
        return False

    @property
    def shelf(self) -> bool:
        """May be scanned with depth = 0"""
        return True
