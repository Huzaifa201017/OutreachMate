from enum import Enum


class EmailConstants(str, Enum):
    # Providers
    GMAIL = "gmail"
    OUTLOOK = "outlook"

    # OAuth Scopes
    GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
    GMAIL_USER_INFO = "https://www.googleapis.com/auth/userinfo.email"
    OPENID = "openid"

    # OAuth Settings
    OAUTH_STATE_PREFIX = "oauth_state"
    OAUTH_ACCESS_TYPE = "offline"
