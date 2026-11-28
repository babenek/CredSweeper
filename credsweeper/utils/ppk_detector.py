import contextlib
import logging
import re
import string
from typing import List

from credsweeper.common.constants import PPK_BEGIN_PATTERN, PPK_END_PATTERN, MAX_LINE_LENGTH
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.utils.util import Util
from credsweeper.utils.pem_key_detector import PemKeyDetector

logger = logging.getLogger(__name__)


class PpkDetector(PemKeyDetector):
    """Class to detect unencrypted PuTTY private key"""
    # unencrypted keys detection only
    PPK_END_RE_PATTERN = re.compile(fr"{PPK_END_PATTERN}[0-9a-f]{32 - 128}")
    ENCRYPTION_NONE = "Encryption: none"
    IGNORE_STARTS = (PPK_BEGIN_PATTERN, ENCRYPTION_NONE, "Comment:", "Public-Lines:", "Private-Lines:")
    WRAP_CHARACTERS = "\\'\"`;,[]#*!"
    REMOVE_CHARACTERS = string.whitespace + WRAP_CHARACTERS

    # last line contains 4 symbols, at least

    def detect(self, first_line: LineData, target: AnalysisTarget) -> List[LineData]:
        """Detects PPK format in single line and with iterative for next lines according
        https://putty.org.ru/manual/appendixC

        Args:
            first_line: detected PuTTY-User-Key-File- from rule pattern
            target: Analysis target

        Return:
            List of LineData with found PPK

        """
        line_data_list: List[LineData] = []
        key_data_list: List[str] = []
        # escaped key in one line with prefixes
        ppk_end_limit = min(target.line_len, first_line.value_start + PemKeyDetector.MAX_PEM_LENGTH)
        if end_match := PpkDetector.PPK_END_RE_PATTERN.search(target.line, first_line.value_start, ppk_end_limit):
            first_line_end_pattern_start = end_match.start(0)
            first_line_end_pattern_end = end_match.end(0)
        else:
            first_line_end_pattern_start = -2
            first_line_end_pattern_end = -2
        if first_line.value_start < first_line_end_pattern_start < first_line_end_pattern_end:
            # the whole PPK in single line
            ppk_text = target.line[first_line.value_start:first_line_end_pattern_end]
            first_line.value = ppk_text
            first_line.value_end = first_line.value_start + len(ppk_text)
            line_data_list.append(first_line)
        else:
            line_data_list.append(first_line)
            ppk_text = first_line.line[first_line.value_start:first_line.value_start + PemKeyDetector.MAX_PEM_LENGTH]
            # perhaps, in next lines
            start_pos = max(0, target.line_pos) + 1
            end_pos = min(start_pos + 200, target.lines_len)
            for line_pos in range(start_pos, end_pos):
                target_line = target.lines[line_pos]
                if end_match := PpkDetector.PPK_END_RE_PATTERN.search(target_line, 0, PemKeyDetector.MAX_PEM_LENGTH):
                    end_pattern_start = end_match.start(0)
                    end_pattern_end = end_match.end(0)
                else:
                    end_pattern_start = -2
                    end_pattern_end = -2
                if 0 <= end_pattern_start < end_pattern_end:
                    ppk_line = target_line[:end_pattern_end]
                else:
                    ppk_line = target_line[:PemKeyDetector.MAX_PEM_LENGTH]
                next_line = LineData(self._config, target_line, line_pos, target.line_nums[line_pos], target.file_path,
                                     target.file_type, target.info, PemKeyDetector.RE_PEM_VALUE)
                line_data_list.append(next_line)
                ppk_text += f"\n{ppk_line}"
                if PPK_END_PATTERN in ppk_line:
                    break
                if PemKeyDetector.MAX_PEM_LENGTH < len(ppk_text):
                    logger.debug("PPK text oversize %s", target.descriptor)
                    return []
            else:
                logger.debug("PPK end not found %s", target.descriptor)
                return []

        while "\\\\" in ppk_text:
            # reduce JSON escaping sequences of backslash
            ppk_text = ppk_text.replace("\\\\", '\\')

        # replace escaped line ends with real and process them - PPK does not contain '\' sign
        ppk_text = ppk_text.replace("\\r\\n", '\n').replace("\\r", '\n').replace("\\n", '\n').replace("\\t", '\t')
        ppk_lines = ppk_text.splitlines()
        self.set_barrier(ppk_lines[-1])
        for subline in ppk_lines:
            if PpkDetector.is_leading_config_line(subline):
                continue
            _subline = self.cut_barrier(subline)
            if sanitized_line := PpkDetector.sanitize_line(_subline):
                if PPK_END_PATTERN in sanitized_line:
                    return PpkDetector.finalize(line_data_list, key_data_list, sanitized_line)
                # the end is not reached - sanitize the data
                # PPK key line should not contain spaces or . (and especially not ...)
                if not PpkDetector.RE_BASE64_CHARS.fullmatch(sanitized_line):
                    return []
                key_data_list.append(sanitized_line)
        return []

    @staticmethod
    def finalize(line_data_list: List[LineData], key_data_list: List[str], last_line: str) -> List[LineData]:
        """Checks collected key_data according the key type"""
        if len(key_data_list) < len(line_data_list):
            PpkDetector.sanitize_line_data_list(line_data_list, key_data_list, last_line)
        key_data = ''.join(key_data_list)
        return line_data_list

    @staticmethod
    def is_leading_config_line(line: str) -> bool:
        """Detect skipping lines which are not base64 data"""
        if not line:
            return True
        for ignore_string in PpkDetector.IGNORE_STARTS:
            if ignore_string in line:
                return True
        return False
