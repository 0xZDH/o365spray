#!/usr/bin/env python3

from datetime import datetime

# Get the current time in YYMMDDHHMM format to append
# to file names to keep each run distinct
F_TIME = datetime.now().strftime("%y%m%d%H%M")


class DefaultFiles:
    """Global output file name defaults"""

    # Log and valid output files
    LOG_FILE = "raw.log"
    ENUM_FILE = f"enum_valid_accounts.{F_TIME}.txt"
    SPRAY_FILE = f"spray_valid_credentials.{F_TIME}.txt"

    # Tested files
    ENUM_TESTED = f"enum_tested_accounts.{F_TIME}.txt"
    SPRAY_TESTED = f"spray_tested_credentials.{F_TIME}.txt"

    # Misc. files
    ENUM_IDP = f"enum_found_idp_accounts.{F_TIME}.txt"


class Defaults:
    """Global default values"""

    # ANSI escape code to clear line
    ERASE_LINE = "\x1b[2K"

    # Valid requests.request methods to work with
    HTTP_METHODS = ["get", "options", "head", "post", "put", "patch", "delete"]

    # HTTP Header Configuration
    HTTP_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
    # https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f
    # This will be used for both Autodiscover and Azure AD
    AADSTS_CODES = {
        "AADSTS50053": ["LOCKED", "Account locked"],
        "AADSTS50055": ["EXPIRED_PASS", "Password expired"],
        "AADSTS50057": ["DISABLED", "User disabled"],
        "AADSTS50126": ["INVALID_CREDS", "Invalid username or password"],
        "AADSTS50059": ["MISSING_TENANT", "Tenant for account doesn't exist"],
        "AADSTS50128": ["INVALID_DOMAIN", "Tenant for account doesn't exist"],
        "AADSTS50034": ["USER_NOT_FOUND", "User does not exist"],
        "AADSTS50079": ["VALID_MFA", "Response indicates MFA (Microsoft)"],
        "AADSTS50076": ["VALID_MFA", "Response indicates MFA (Microsoft)"],
        "AADSTS50158": [
            "SEC_CHAL",
            "Response indicates conditional access (MFA: DUO or other)",
        ],
        "AADSTS500011": ["INVALID_RESOURCE", "Invalid resource name"],
        "AADSTS700016": ["INVALID_APPID", "Invalid application client ID"],
    }

    # List of substrings that can be found when BasicAuth is blocked
    BASICAUTH_ERRORS = [
        "Basic Auth Blocked",
        "BasicAuthBlockStatus - Deny",
        "BlockBasicAuth - User blocked",
    ]
