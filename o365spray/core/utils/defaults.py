#!/usr/bin/env python3

import sys
import asyncio
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
        "DNT": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
    }

    # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
    # fmt: off
    AADSTS_CODES = {
        "AADSTS50053":  ["LOCKED",           "Account locked"],
        "AADSTS50055":  ["EXPIRED_PASS",     "Password expired"],
        "AADSTS50057":  ["DISABLED",         "User disabled"],
        "AADSTS50126":  ["INVALID_CREDS",    "Invalid username or password"],
        "AADSTS50059":  ["MISSING_TENANT",   "Tenant for account doesn't exist"],
        "AADSTS50128":  ["INVALID_DOMAIN",   "Tenant for account doesn't exist"],
        "AADSTS50034":  ["USER_NOT_FOUND",   "User does not exist"],
        "AADSTS50079":  ["VALID_MFA",        "Response indicates MFA (Microsoft)"],
        "AADSTS50076":  ["VALID_MFA",        "Response indicates MFA (Microsoft)"],
        "AADSTS50158":  ["SEC_CHAL",         "Response indicates conditional access (MFA: DUO or other)"],
        "AADSTS500011": ["INVALID_RESOURCE", "Invalid resource name"],
        "AADSTS700016": ["INVALID_APPID",    "Invalid application client ID"],
        "AADSTS53003":  ["VALID_CAP",        "Access blocked via Conditional Access Policies"],
    }
    # fmt: on

    # List of valid AADSTS codes to check against
    VALID_AADSTS_CODES = [
        "AADSTS500011",  # INVALID_RESOURCE
        "AADSTS700016",  # INVALID_APPID
        "AADSTS50055",  # EXPIRED_PASS
        "AADSTS50079",  # VALID_MFA
        "AADSTS50076",  # VALID_MFA
        "AADSTS50158",  # SEC_CHAL
        "AADSTS53003",  # VALID_CAP
    ]

    # List of substrings that can be found when BasicAuth is blocked
    BASICAUTH_ERRORS = [
        "Basic Auth Blocked",
        "BasicAuthBlockStatus - Deny",
        "BlockBasicAuth - User blocked",
    ]

    # Create a type handler for asyncio loops based on operating system
    if sys.platform == "win32":
        # windows
        EventLoop = asyncio.windows_events.ProactorEventLoop
    else:
        # darwin/linux
        EventLoop = asyncio.unix_events._UnixSelectorEventLoop
