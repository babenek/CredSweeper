import unittest

import deepdiff  # type: ignore

from credsweeper.app import CredSweeper
from credsweeper.common.constants import Severity
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_provider import TextProvider
from tests import SAMPLES_PATH


class TestDoc(unittest.TestCase):

    def test_ip_id_passwd_triple_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "doc_ip_id_password_triple"])
        cred_sweeper = CredSweeper(doc=True, severity=Severity.CRITICAL)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(5, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_passwd_pair_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "doc_id_password_pair"])
        cred_sweeper = CredSweeper(doc=True, severity=Severity.CRITICAL)
        cred_sweeper.run(content_provider=content_provider)
        found_credentials = cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(15, len(found_credentials), found_credentials)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
