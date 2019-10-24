#!/usr/bin/env python3

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

# MSOnline data
msonline = {
    # getuserrealm seems to be considerably faster when identifying if a domain uses O365
    "url":  "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1",
    "url2": "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration"
}

# Autodiscover data
autodiscover = {
    "url": "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml",
    "enum_url": "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{EMAIL}?Protocol=Autodiscoverv1",
    "status_codes": {
        200: "VALID_CREDS",
        456: "FOUND_CREDS"
    },
    "enum_codes": {
        "good": [200],
        "bad": [302]
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
    "enum_url": "https://outlook.office365.com/Microsoft-Server-ActiveSync",
    "status_codes": {
        200: "VALID_CREDS",
        403: "FOUND_CREDS"
    },
    "enum_codes": {
        "good": [200, 403, 401],
        "bad": [404]
    }
}