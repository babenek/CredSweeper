from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider


class DataContentProvider(ContentProvider):
    """Dummy raw provider to keep bytes

    Parameters:
        content: byte sequence to be stored.
        file_path: optional string. Might be specified if you know true file name lines was taken from.

    """

    def __init__(self, content: bytes, file_path: Optional[str] = None) -> None:
        super().__init__(file_path if file_path is not None else "")
        self.__data = content

    @property
    def data(self) -> bytes:
        """data getter"""
        return self.__data

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Return empty list lines.

        Return:
            list of analysis targets based on every row in a content

        """
        return []
