import csv
import io
import logging
from abc import ABC
from typing import List, Optional, Dict, Any

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class CsvScanner(AbstractScanner, ABC):
    """Implements eml scanning"""

    sniffer = csv.Sniffer()
    delimiters = ''.join(sniffer.preferred)

    @classmethod
    def get_structure(cls, text: str) -> List[Dict[str, Any]]:
        # windows style \r\n
        first_line_end = text.find('\r', 0, MAX_LINE_LENGTH)
        line_terminator = "\r\n"
        if 0 > first_line_end:
            # unix style \n
            first_line_end = text.find('\n', 0, MAX_LINE_LENGTH)
            line_terminator = "\n"
            if 0 > first_line_end:
                raise ValueError(f"No suitable line end found in {MAX_LINE_LENGTH} symbols")

        dialect = cls.sniffer.sniff(text[:first_line_end], delimiters=cls.delimiters)
        rows = []
        for row in csv.DictReader(io.StringIO(text), delimiter=dialect.delimiter, lineterminator=line_terminator):
            if not isinstance(row, dict):
                raise RuntimeError(f"ERROR: wrong row '{row}' in ")
            print(row)
            rows.append(row)
        return rows

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan EML with text representation"""
        try:
            rows = self.get_structure(data_provider.text)
            struct_content_provider = StructContentProvider(struct=rows,
                                                            file_path=data_provider.file_path,
                                                            file_type=data_provider.file_type,
                                                            info=f"{data_provider.info}|CSV")
            new_limit = recursive_limit_size - sum(len(x) for x in rows)
            candidates = self.structure_scan(struct_content_provider, depth, new_limit)
            return candidates
        except Exception as csv_exc:
            logger.error(f"{data_provider.file_path}:{csv_exc}")
        return None
