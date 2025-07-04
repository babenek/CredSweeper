from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import (ValueAllowlistCheck, ValueArrayDictionaryCheck, ValueBlocklistCheck,
                                 ValueCamelCaseCheck, ValueDictionaryValueLengthCheck, ValueFilePathCheck,
                                 ValueLastWordCheck, ValueMethodCheck, ValueNotAllowedPatternCheck, ValuePatternCheck,
                                 ValueStringTypeCheck, ValueTokenCheck)
from credsweeper.filters.group.group import Group


class UrlCredentialsGroup(Group):
    """UrlCredentialsGroup"""

    def __init__(self, config: Config) -> None:
        """URL credentials group class.

        Similar to PasswordKeyword, but exclude all checks dependent on the variable name, as URL credentials have no
        explicitly defined variable
        """
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueAllowlistCheck(),
            ValueArrayDictionaryCheck(),
            ValueBlocklistCheck(),
            ValueCamelCaseCheck(),
            ValueFilePathCheck(),
            ValueLastWordCheck(),
            ValueMethodCheck(),
            ValueStringTypeCheck(config),
            ValueNotAllowedPatternCheck(),
            ValueTokenCheck(),
            ValueDictionaryValueLengthCheck(min_len=4, max_len=80),
            ValuePatternCheck(pattern_len=config.pattern_len)
        ]
