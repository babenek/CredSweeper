import logging
import re
from abc import ABC
from typing import List, Optional

from lxml import etree

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class XmlScanner(AbstractScanner, ABC):
    """Realises xml scanning"""

    # A well-formed XML must start from < or a whitespace character
    XML_FIRST_BRACKET_PATTERN = re.compile(rb"^\s*<")
    XML_OPENING_TAG_PATTERN = re.compile(rb"<([0-9A-Za-z_]{1,256})")

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Used to detect xml format from raw bytes"""
        if XmlScanner.XML_FIRST_BRACKET_PATTERN.search(data, 0, MAX_LINE_LENGTH):
            if first_bracket_match := XmlScanner.XML_OPENING_TAG_PATTERN.search(data, 0, MAX_LINE_LENGTH):
                start_pos = first_bracket_match.start()
                closing_tag = b"</" + first_bracket_match.group(1) + b">"
                if start_pos < data.find(closing_tag, start_pos):
                    return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as xml text and scan as text lines"""
        try:
            structure = etree.fromstringlist(data_provider.lines)
            struct_data_provider = StructContentProvider(struct=structure,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|XML")
            new_limit = recursive_limit_size - len(data_provider.data)
            candidates = self.structure_scan(struct_data_provider, depth, new_limit)
            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as XML %s:%s %s", type(exc), exc, data_provider.descriptor)
        return None
