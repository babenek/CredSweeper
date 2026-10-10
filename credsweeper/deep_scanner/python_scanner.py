import logging
import tomllib
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class PythonScanner(AbstractScanner, ABC):
    """Implements Python scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check if data MAY be in TOML format"""
        if (0 < data.find(b';', 0, MAX_LINE_LENGTH) or 2 < data.count(b'\n', 0, MAX_LINE_LENGTH)) \
                and (0 <= data.find(b'"', 0, MAX_LINE_LENGTH) or 0 <= data.find(b"'", 0, MAX_LINE_LENGTH)):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan each row as structure with column name in key"""
        try:
            if structure := Util.parse_python(data_provider.text):
                struct_content_provider = StructContentProvider(struct=structure,
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|Python")
                new_limit = recursive_limit_size - len(data_provider.text)
                struct_candidates = self.structure_scan(struct_content_provider, depth, new_limit)
                return struct_candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.log(TRACE, "Cannot parse as Python %s:%s %s", type(exc), exc, data_provider.descriptor)
        return None
