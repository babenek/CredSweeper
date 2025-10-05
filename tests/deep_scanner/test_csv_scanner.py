import unittest

from credsweeper.deep_scanner.csv_scanner import CsvScanner
from tests import AZ_STRING


class TestCsvScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_get_structure_n(self):
        with self.assertRaises(Exception):
            CsvScanner.get_structure(f"{AZ_STRING[:19]}\n{AZ_STRING[20:]}\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure("'user and password'\nadmin&tizen\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure('')
        with self.assertRaises(Exception):
            CsvScanner.get_structure("user&password\nadmin&tizen\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure('"user and password"\nadmin&tizen\n')
        with self.assertRaises(ValueError):
            CsvScanner.get_structure("user,password\tadmin,tizen\t")

    def test_get_structure_p(self):
        structure = CsvScanner.get_structure("user,password\nadmin,tizen\n")
        self.assertIsInstance(structure, list)
        self.assertEqual(1, len(structure))
        self.assertDictEqual({'password': 'tizen', 'user': 'admin'}, structure[0])
        #CsvScanner.get_structure("Feuer und Wasser\ncommt nicht zusammen\n")