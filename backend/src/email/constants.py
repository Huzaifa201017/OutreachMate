from enum import Enum


class EmailConstants(str, Enum):
    # Providers
    GMAIL = "gmail"

    # OAuth Settings
    OAUTH_STATE_PREFIX = "oauth_state"
    OAUTH_ACCESS_TYPE = "offline"
