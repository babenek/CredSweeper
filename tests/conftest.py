import datetime
from argparse import Namespace
from typing import Optional

import pytest

from credsweeper.app import APP_PATH
from credsweeper.common.constants import Severity
from credsweeper.config.config import Config
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util
from tests import SAMPLES_PATH


@pytest.fixture
def python_file_path() -> str:
    return f"test_file_{str(datetime.datetime.now())}.py"


@pytest.fixture
def file_path() -> str:
    return f"test_file_{str(datetime.datetime.now())}"


@pytest.fixture
def args() -> Namespace:
    file_name = SAMPLES_PATH / "password.gradle"
    return Namespace(path=[file_name], json_filename=None)


@pytest.fixture
def config() -> Config:
    file_name = APP_PATH / "secret" / "config.json"
    config_dict = Util.json_load(file_name)

    config_dict["use_filters"] = True
    config_dict["find_by_ext"] = False
    config_dict["exclude"]["containers"] = [".gz", ".zip"]
    config_dict["exclude"]["documents"] = [".docx", ".pdf"]
    config_dict["exclude"]["extension"] = [".jpg", ".bmp"]
    config_dict["depth"] = 0
    config_dict["doc"] = False
    config_dict["find_by_ext_list"] = [".txt", ".inf"]
    config_dict["size_limit"] = None
    config_dict["severity"] = Severity.INFO
    return Config(config_dict)


@pytest.fixture
def rule(rule_name: str, config: Config, rule_path: str) -> Optional[Rule]:
    scanner = Scanner(config, rule_path)
    for rule, scanner in scanner.rules_scanners:
        if rule.rule_name == rule_name:
            return rule
    return None


@pytest.fixture
def rule_path() -> str:
    return str(APP_PATH / "rules" / "config.yaml")


@pytest.fixture
def scanner(rule: Rule, config: Config, rule_path: str) -> Scanner:
    scanner = Scanner(config, rule_path)
    scanner.rules_scanners = [(rule, Scanner.get_scanner(rule))]
    return scanner


@pytest.fixture
def scanner_without_filters(rule: Rule, config: Config, rule_path: str):
    config.use_filters = False
    scanner = Scanner(config, rule_path)
    scanner.rules_scanners = [(rule, Scanner.get_scanner(rule))]
    return scanner
