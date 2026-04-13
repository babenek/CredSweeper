import contextlib
import struct
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueCipherTextCheck(Filter):
    """
    Check that candidate is base64 encoded cipher text of aws-kms
    https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html
    """

    ALGORITHM_IDS = {0x0014, 0x0046, 0x0078, 0x0114, 0x0146, 0x0178, 0x0214, 0x0346, 0x0378, 0x0478, 0x0578}

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received weird base64 token which must be a random string

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        value = line_data.value
        if 170 > len(value) and not value.startswith('A'):
            # a ciphertext must be at least 128 bytes in decoded and has 000000 in first symbol
            return False
        with contextlib.suppress(Exception):
            decoded = Util.decode_base64(value, padding_safe=False, urlsafe_detect=True)
            match decoded[0]:
                case 0x01:
                    header_v1 = struct.unpack_from(">BH16sH", decoded, offset=1)
                    if (0x80 == header_v1[0] and header_v1[1] in ValueCipherTextCheck.ALGORITHM_IDS
                            and header_v1[3] < len(decoded) - 22):
                        return True
                case 0x02:
                    header_v2 = struct.unpack_from(">H32sH", decoded, offset=1)
                    if header_v2[0] in ValueCipherTextCheck.ALGORITHM_IDS and header_v2[2] < len(decoded) - 22:
                        return True
            if b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07" in decoded:
                # 1.2.840.113549.1.7
                return True
            else:
                return False
        return False
