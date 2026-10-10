import json
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class JsonScanner(AbstractScanner, ABC):
    """Implements scanning of data if it is a script of some markup language"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check matches for a json simple format"""
        if 0 < data.find(b'"', 0, MAX_LINE_LENGTH):
            # each valuable json has the text marker
            if 0 < data.find(b':', 0, MAX_LINE_LENGTH):
                # key - value json
                if 0 <= data.find(b'{', 0, MAX_LINE_LENGTH):
                    start = max(0, len(data) - MAX_LINE_LENGTH)
                    if data.rfind(b'}', start):
                        return True
            else:
                if 0 <= data.find(b'[', 0, MAX_LINE_LENGTH):
                    start = max(0, len(data) - MAX_LINE_LENGTH)
                    if data.rfind(b']', start):
                        return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as markup language and scan as structure"""

        new_limit = recursive_limit_size - len(data_provider.data)

        try:
            ndjson_candidates = []
            for n, line in enumerate(self.text.splitlines(), start=1):
                # each line must be in json format, otherwise - exception rises
                structure = json.loads(line)
                struct_data_provider = StructContentProvider(struct=structure,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|NDJSON[{n}]")
                candidates = self.structure_scan(struct_data_provider, depth, new_limit)
                ndjson_candidates.extend(candidates)
            return ndjson_candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as ndjson %s:%s %s", type(exc), exc, data_provider.descriptor)

        try:
            structure = json.loads(data_provider.text)
            struct_data_provider = StructContentProvider(struct=structure,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|JSON")
            candidates = self.structure_scan(struct_data_provider, depth, new_limit)
            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as json %s:%s %s", type(exc), exc, data_provider.descriptor)

        return None
