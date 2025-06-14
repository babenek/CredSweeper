from copy import deepcopy
from typing import Any

import pytest

from credsweeper.common.constants import Severity, RuleType
from credsweeper.config.config import Config
from credsweeper.filters.group import GeneralPattern
from credsweeper.rules.rule import Rule


class TestRuleConfigParsing:

    @pytest.fixture(params=[
        # Check proper config
        {
            "name": "Twilio API Key",
            "severity": "high",
            "confidence": "moderate",
            "type": "pattern",
            "values": ["(?P<value>SK[0-9a-fA-F]{32})"],
            "filter_type": GeneralPattern.__name__,
            "min_line_len": 32,
            "use_ml": False,
            "target": ["code", "doc"],
        },
        # Check proper config with no filters
        {
            "name": "Twilio API Key",
            "severity": "high",
            "confidence": "moderate",
            "type": "pattern",
            "values": ["(?P<value>SK[0-9a-fA-F]{32})"],
            "filter_type": [],
            "min_line_len": 32,
            "use_ml": False,
            "target": ["code", "doc"],
        },
    ])
    def rule_config(self, request: str) -> Any:
        return deepcopy(request.param)

    def test_create_from_config_p(self, config: Config, rule_config: pytest.fixture) -> None:
        rule = Rule(config, rule_config)
        assert rule.rule_type == RuleType.PATTERN
        assert rule.patterns[0].pattern == "(?P<value>SK[0-9a-fA-F]{32})"
        assert rule.rule_name == "Twilio API Key"
        assert rule.severity == Severity.HIGH

    @pytest.mark.parametrize("field, error", [["severity", "none"], ["type", "none"], ["filter_type", "none"]])
    def test_create_from_malformed_config_n(self, config: Config, rule_config: pytest.fixture, field: str,
                                            error: str) -> None:
        rule_config[field] = error
        with pytest.raises(ValueError, match=r"Malformed .*"):
            Rule(config, rule_config)

    def test_create_from_missing_fields_n(self, config: Config) -> None:
        with pytest.raises(ValueError, match=r"Malformed rule config file. Contain rule with missing fields:.*"):
            Rule(config, {})
