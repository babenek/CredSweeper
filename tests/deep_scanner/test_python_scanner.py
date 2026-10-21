import unittest

from credsweeper.deep_scanner.python_scanner import PythonScanner


class TestPythonScanner(unittest.TestCase):


    def test_parse_py_p(self):
        result = PythonScanner.parse("""password = \
        "Hello" \
        ' World!'""")
        self.assertIsInstance(result, list)
        self.assertListEqual(["password = 'Hello World!'"], result)

    def test_parse_py_n(self):
        # empty
        self.assertTrue(PythonScanner.parse("""regexa=r'\.'"""))
        self.assertFalse(PythonScanner.parse(''))
        # wrong syntax
        with self.assertRaises(SyntaxError):
            PythonScanner.parse("""<html>"Hello World!"</html>""")
        with self.assertRaises(SyntaxError):
            PythonScanner.parse("""{'wrong': ': '"\." is syntax warning'}""")

    def test_match_p(self):
        self.assertTrue(PythonScanner.match(b'cred=[\n"test"\n]\n'))

    def test_match_n(self):
        with self.assertRaises(AttributeError):
            self.assertFalse(PythonScanner.match(None))
        self.assertFalse(PythonScanner.match(b''))
        self.assertFalse(PythonScanner.match(b'%Python+'))
