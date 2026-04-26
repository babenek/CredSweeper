import contextlib
import logging
import re
import string
from typing import List

from credsweeper.common.constants import PEM_BEGIN_PATTERN, PEM_END_PATTERN, Chars, MAX_LINE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)

ENTROPY_LIMIT_BASE64 = 4.5


class PemKeyDetector:
    """Class to detect PEM PRIVATE keys only"""
    base64set = set(Chars.BASE64STDPAD_CHARS.value)

    ignore_starts = [PEM_BEGIN_PATTERN, "Proc-Type", "Version", "DEK-Info"]
    wrap_characters = "\\'\";,[]#*!"
    remove_characters = string.whitespace + wrap_characters
    # last line contains 4 symbols, at least
    re_pem_begin = re.compile(r"(?P<value>" + PEM_BEGIN_PATTERN +
                              r"[^-]{1,80}(?!ENCRYPTED)[^-]{0,80}PRIVATE[^-]{1,80}KEY[^-]{0,80}-----(.{1,8000}" +
                              PEM_END_PATTERN + r"[^-]{1,80}KEY[^-]{0,80}-----)?)")
    re_value_pem = re.compile(r"(?P<value>" + PEM_END_PATTERN + r"[^-]{1,80}-----|([a-zA-Z0-9/+=]{4})+)")

    def __init__(self, config: Config):
        self.__config = config
        self._barrier_pos: int = -2
        self._barrier_cut: int = -2
        self._barrier: str = ''

    def cut_barrier(self, line: str) -> str:
        """Cut off barrier if detected"""
        if self._barrier and 0 <= self._barrier_pos < self._barrier_cut < len(line):
            if line[self._barrier_pos] == self._barrier:
                return line[self._barrier_cut:]
            self._barrier = ''
        return line

    def set_barrier(self, line: str, start=0, end=MAX_LINE_LENGTH):
        """Detects barrier with offset of PEM_BEGIN_PATTERN"""
        self._barrier = ''
        self._barrier_cut = line.find(PEM_BEGIN_PATTERN, start, end)
        self._barrier_pos = self._barrier_cut - 1
        if 0 <= self._barrier_pos < self._barrier_cut<len(line):
            barrier = line[self._barrier_pos]
            if barrier not in PemKeyDetector.base64set:
                self._barrier = barrier

    def detect_pem_key(self, target: AnalysisTarget) -> List[LineData]:
        """Detects PEM key in single line and with iterative for next lines according
        https://www.rfc-editor.org/rfc/rfc7468

        Args:
            target: Analysis target

        Return:
            List of LineData with found PEM

        """
        line_data_list: List[LineData] = []
        key_data = ""
        # get line with -----BEGIN which may contain full key
        first_line = LineData(self.__config, target.line, target.line_pos, target.line_num, target.file_path,
                              target.file_type, target.info, PemKeyDetector.re_pem_begin)
        line_data_list.append(first_line)
        # protection check for case when first line starts from 0
        start_pos = target.line_pos if 0 <= target.line_pos else 0
        finish_pos = min(start_pos + 200, target.lines_len)
        begin_pattern_not_passed = True
        for line_pos in range(start_pos, finish_pos):
            line = target.lines[line_pos]
            if target.line_pos != line_pos:
                _line = self.cut_barrier(line)
                line_data = LineData(self.__config, _line, line_pos, target.line_nums[line_pos], target.file_path,
                                     target.file_type, target.info, PemKeyDetector.re_value_pem)
                if len_diff := len(line) - len(_line):
                    # restore line like in target if barrier detected
                    line_data.line = line
                    line_data.value_start += len_diff
                    line_data.value_end += len_diff
                line_data_list.append(line_data)
            # replace escaped line ends with real and process them - PEM does not contain '\' sign
            while "\\\\" in line:
                line = line.replace("\\\\", "\\")
            sublines = line.replace("\\r\\n", '\n').replace("\\r", '\n').replace("\\n", '\n').splitlines()
            for subline in sublines:
                if begin_pattern_not_passed or PemKeyDetector.is_leading_config_line(subline):
                    # some offset of begin helps to sanitize a log prefix
                    if PEM_BEGIN_PATTERN in subline:
                        self.set_barrier(subline)
                        begin_pattern_not_passed = False
                    continue
                _subline = self.cut_barrier(subline)
                if PEM_END_PATTERN in _subline:
                    if PemKeyDetector.finalize(target, key_data):
                        return line_data_list
                    return []
                # the end is not reached - sanitize the data
                sanitized_line = PemKeyDetector.sanitize_line(_subline)
                # PEM key line should not contain spaces or . (and especially not ...)
                for i in sanitized_line:
                    if i not in PemKeyDetector.base64set:
                        return []
                key_data += sanitized_line
        return []

    @classmethod
    def finalize(cls, target: AnalysisTarget, key_data: str) -> bool:
        if "PGP" in target.line_strip:
            # Check if entropy is high enough for base64 set with padding sign
            entropy = Util.get_shannon_entropy(key_data)
            if ENTROPY_LIMIT_BASE64 <= entropy:
                return True
            logger.debug("Filtered with entropy %f '%s'", entropy, key_data)
        if "OPENSSH" in target.line_strip:
            # Check whether the key is encrypted
            with contextlib.suppress(Exception):
                decoded = Util.decode_base64(key_data, urlsafe_detect=True)
                if 32 < len(decoded) and b"bcrypt" not in decoded:
                    # 256 bits is the minimal size of Ed25519 keys
                    # all OK - the key is not encrypted in this top level
                    return True
            logger.debug("Filtered with size or bcrypt '%s'", key_data)
        else:
            with contextlib.suppress(Exception):
                if decoded := Util.decode_base64(key_data, padding_safe=True, urlsafe_detect=True):
                    if len(decoded) == Util.get_asn1_size(decoded):
                        # all OK - the key is not encrypted in this top level
                        return True
            logger.debug("Filtered with non asn1 '%s'", key_data)
        return False

    @classmethod
    def sanitize_line(cls, line: str, recurse_level: int = 5) -> str:
        """Remove common symbols that can surround PEM keys inside code.

        Examples::

            `# ZZAWarrA1`
            `* ZZAWarrA1`
            `  "ZZAWarrA1\\n" + `

        Args:
            line: Line to be cleaned
            recurse_level: to avoid infinite loop in case when removed symbol inside base64 encoded

        Return:
            line with special characters removed from both ends

        """
        recurse_level -= 1

        if 0 > recurse_level:
            return line

        # Note that this strip would remove `\n` but not `\\n`
        line = line.strip(string.whitespace)
        if line.startswith("//"):
            # simplify first condition for speed-up of doxygen style processing
            if line.startswith(("// ", "/// ")):
                # Assume that the commented line is to be separated from base64 code, it may be a part of PEM, otherwise
                line = line[3:]
        if line.startswith("/*"):
            line = line[2:]
        if line.endswith("*/"):
            line = line[:-2]
        if line.endswith("\\"):
            # line carry in many languages
            line = line[:-1]

        # remove concatenation carefully only when it is not part of base64
        if line.startswith('+') and 1 < len(line) and line[1] not in PemKeyDetector.base64set:
            line = line[1:]
        if line.endswith('+') and 2 < len(line) and line[-2] not in PemKeyDetector.base64set:
            line = line[:-1]

        line = line.strip(PemKeyDetector.remove_characters)
        # check whether new iteration requires
        for x in string.whitespace:
            if line.startswith(x) or line.endswith(x):
                return PemKeyDetector.sanitize_line(line, recurse_level=recurse_level)

        for x in PemKeyDetector.wrap_characters:
            if x in line:
                return PemKeyDetector.sanitize_line(line, recurse_level=recurse_level)

        return line

    @classmethod
    def is_leading_config_line(cls, line: str) -> bool:
        """Remove non-key lines from the beginning of a list.

        Example lines with non-key leading lines:

        .. code-block:: text

            Proc-Type: 4,ENCRYPTED
            DEK-Info: DEK-Info: AES-256-CBC,2AA219GG746F88F6DDA0D852A0FD3211

            ZZAWarrA1...

        Args:
            line: Line to be checked

        Return:
            True if the line is not a part of encoded data but leading config

        """
        if 0 == len(line):
            return True
        for ignore_string in PemKeyDetector.ignore_starts:
            if ignore_string in line:
                return True
        return False
