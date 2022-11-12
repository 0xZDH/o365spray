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
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Upgrade-Insecure-Requests": "1",
    }

    # Valid scopes, resources, and client IDs for OAuth authentication and enumeration
    SCOPES = [
        ".default",
        "openid",
        "profile",
        "offline_access",
    ]

    RESOURCES = [
        "graph.windows.net",
        "graph.microsoft.com",
    ]

    # https://github.com/secureworks/TokenMan#foci-application-client-id-map
    CLIENT_IDS = [
        "a40d7d7d-59aa-447e-a655-679a4107e548",  # Accounts Control UI
        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",  # Microsoft Edge
        "e9c51622-460d-4d3d-952d-966a5b1da34c",  # Microsoft Edge (1)
        "ecd6b820-32c2-49b6-98a6-444530e5a77a",  # Microsoft Edge AAD BrokerPlugin
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",  # Microsoft Intune Company Portal
        "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",  # Microsoft Power BI
        "22098786-6e16-43cc-a27d-191a01a1e3b5",  # Microsoft To-Do client
        "eb539595-3fe1-474e-9c1d-feb3625d1be5",  # Microsoft Tunnel
        "57336123-6e14-4acc-8dcf-287b6088aa28",  # Microsoft Whiteboard Client
        "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive SyncEngine
        "4e291c71-d680-4d0e-9640-0a3358e31177",  # PowerApps
        "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",  # Visual Studio
        "26a7ee05-5602-4d76-a7ba-eae8b7b67941",  # Windows Search
    ]

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
