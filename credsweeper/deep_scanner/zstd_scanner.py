import logging
from abc import ABC
from compression import zstd
from typing import List, Optional

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class ZstdScanner(AbstractScanner, ABC):
    """Implements zstd data inflate and scan"""

    @staticmethod
    def match(data: bytes) -> bool:
        """Returns True if data looks like deflated data with zstd"""
        if data.startswith(b"\x28\xB5\x2F\xFD") and 20 < len(data):
            # around 20 bytes for 8 bytes
            return True
        return False

    @staticmethod
    def decompress(limit: int, data: bytes) -> None | bytes:
        lower, upper = zstd.DecompressionParameter.window_log_max.bounds()
        log_limit = int.bit_length(limit)
        if log_limit < lower or log_limit > upper:
            return None
        options = {zstd.DecompressionParameter.window_log_max: log_limit}
        return zstd.ZstdDecompressor(options=options).decompress(data, limit)

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Inflate data from zstd compressed and launches data_scan"""
        try:
            if decompressed := ZstdScanner.decompress(recursive_limit_size, data_provider.data):
                zstd_content_provider = DataContentProvider(data=decompressed,
                                                            file_path=data_provider.file_path,
                                                            file_type=data_provider.file_type,
                                                            info=f"{data_provider.info}|ZSTD")
                new_limit = recursive_limit_size - len(decompressed)
                zstd_candidates = self.recursive_scan(zstd_content_provider, depth, new_limit)
                return zstd_candidates
        except Exception as zstd_exc:
            logger.error(f"{data_provider.file_path}:{zstd_exc}")
        return None
