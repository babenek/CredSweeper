from unittest import TestCase

from credsweeper.filters.value_cipher_text_check import ValueCipherTextCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueCipherTextCheck(TestCase):

    def test_run_n(self):
        for line_data in [
            get_line_data(line=x, pattern=LINE_VALUE_PATTERN) for x in [
                "P@5Sw0Rd",  #
                "b2e4d88e6225eba67cddbf02a2f5e18ca056b5c2b2eda98bdb9cd6f0fc52",  #
                "2pwM6fDI/D3glNCfhT51QprOatCTxUdPeU0j0O1rSEmA1KGoIQdeHiD4VdSFSbbi"
                "+8TqpsU3if1fpjmbzy76XOsw28IPTDxwRWJgUB46p5nTsn1zhf2jMU5sMy2984Om"
                "mxWCKrgPVzppC3hAYpvD8nzGjW49E91T+hab6k4j9EgcigC/3GYxTUH8rbZTvQ23"
                "sr8zNXr9",  #
            ]
        ]:
            self.assertFalse(ValueCipherTextCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line_data)

    def test_run_p(self):
        for line_data in [
            get_line_data(line=x, pattern=LINE_VALUE_PATTERN) for x in
            [
                "AgC+dY2eV03Ss2E2icQf4g8zTMwSG8GCxon0b..."
            ]
        ]:
            self.assertTrue(ValueCipherTextCheck().run(line_data, DUMMY_ANALYSIS_TARGET), line_data)
