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


class LangScanner(AbstractScanner, ABC):
    """Implements scanning of data if it is a script of some markup language"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check matches for a JSON & Python format"""
        quot = bool(b'"' in data)
        if quot and 0 <= data.find(b'{', 0, MAX_LINE_LENGTH) and  0 < data.find(b':', 0, MAX_LINE_LENGTH) and 0 < data.rfind(b'}', max(0, len(data) - MAX_LINE_LENGTH)):
            # JSON which requires "key":"value":
            return True
        if quot and 0 <= data.find(b'[', 0, MAX_LINE_LENGTH) and data.rfind(b']',max(0, len(data) - MAX_LINE_LENGTH)):
            # listed JSON or NDJSON
            return True
        # check for python text
        if (quot or b"'" in data) and \
                (0 < data.find(b';', 0, MAX_LINE_LENGTH) or 1 < data.count(b'\n', 0, MAX_LINE_LENGTH)):
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
            for n, line in enumerate(data_provider.text.splitlines(), start=1):
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


class PythonScanner(AbstractScanner, ABC):
    """Implements Python scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check if data MAY be in TOML format"""
        if (0 < data.find(b';', 0, MAX_LINE_LENGTH) or 2 < data.count(b'\n', 0, MAX_LINE_LENGTH)) \
                and (0 <= data.find(b'"', 0, MAX_LINE_LENGTH) or 0 <= data.find(b"'", 0, MAX_LINE_LENGTH)):
            return True
        return False

    MEANINGFUL_NODE_CLASSES = (
        ast.FunctionDef, ast.ClassDef,
    )

    @staticmethod
    def parse(source: str) -> List[Any]:
        """Parse Python source and back to remove strings merge and line wrap"""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("error", SyntaxWarning)
            tree = ast.parse(source)
            tr = {type(node).__name__ for node in ast.walk(tree)}
            result = ast.unparse(tree).splitlines()
            return result

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan each row as structure with column name in key"""
        try:
            if structure := PythonScanner.parse(data_provider.text):
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
