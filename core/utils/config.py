#!/usr/bin/env python3

# == Global Settings
class Config:

    # HTTP Header Configuration
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
    # https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f
    # This will be used for both Autodiscover and Azure AD
    # [Flag, Description, Tab Spacing for Output]
    AADSTS_codes = {
        "AADSTS50053": ["LOCKED", "Account locked", "\t\t"],
        "AADSTS50055": ["EXPIRED_PASS", "Password expired", "\t\t"],
        "AADSTS50057": ["DISABLED", "User disabled", "\t\t"],
        "AADSTS50126": ["INVALID_CREDS", "Invalid username or password", "\t\t"],
        "AADSTS50059": ["MISSING_TENANT", "Tenant for account doesn't exist", "\t"],
        "AADSTS50128": ["INVALID_DOMAIN", "Tenant for account doesn't exist", "\t"],
        "AADSTS50034": ["USER_NOT_FOUND", "User does not exist", "\t"],
        "AADSTS50079": ["VALID_MFA", "Response indicates MFA (Microsoft)", "\t\t"],
        "AADSTS50076": ["VALID_MFA", "Response indicates MFA (Microsoft)", "\t\t"],
        "AADSTS50158": ["SEC_CHAL", "Response indicates conditional access (MFA: DUO or other)", "\t\t"]
    }