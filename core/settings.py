#!/usr/bin/env python3

import requests

# == Global Settings

headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

# == Validate Settings

validate_url = [
    # getuserrealm seems to be considerably faster when identifying if a domain uses O365
    "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1",
    "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration"
]


# == Enum Settings

enum_url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"


# == Spray Settings

# Autodiscover data
autodiscover = {
	"url": "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml",
	"method": requests.get,
    "status_codes": {
        200: "VALID_CREDS",
        456: "FOUND_CREDS"
    },
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
    "AADSTS_codes": {
        "AADSTS50053": ["LOCKED", "Account locked"],
        "AADSTS50055": ["EXPIRED_PASS", "Password expired"],
        "AADSTS50057": ["DISABLED", "User disabled"]
    }
}

# ActiveSync data
activesync = {
	"url": "https://outlook.office365.com/Microsoft-Server-ActiveSync",
	"method": requests.options,
	"status_codes": {
        200: "VALID_CREDS",
        403: "FOUND_CREDS"
        # 401: "BAD_PASSWD"
        # 404: "INVALID_USER"
    }
}