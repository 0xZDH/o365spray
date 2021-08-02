#!/usr/bin/env python3

"""
Based on: https://bitbucket.org/grimhacker/office365userenum/
          https://github.com/Raikia/UhOh365
          https://github.com/nyxgeek/onedrive_user_enum/blob/master/onedrive_enum.py
          https://github.com/gremwell/o365enum/blob/master/o365enum.py
          https://github.com/Gerenios/AADInternals/blob/master/KillChain_utils.ps1#L112
"""

# TODO: Test and validate each active module

import re
import time
import string
import random
import logging
import urllib3
import asyncio
import concurrent.futures
import concurrent.futures.thread
from uuid import uuid4
from typing import List, Dict, Union
from functools import partial
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from o365spray.core.handlers.base import BaseHandler  # type: ignore
from o365spray.core import (  # type: ignore
    Defaults,
    DefaultFiles,
    Helper,
    ThreadWriter,
    text_colors,
)


class Enumerator(BaseHandler):
    """Perform user enumeration against Microsoft O365."""

    HELPER = Helper()  # Helper functions
    VALID_ACCOUNTS = []  # Valid accounts storage

    def __init__(
        self,
        loop: asyncio.unix_events._UnixSelectorEventLoop,
        module: str = "office",
        domain: str = None,
        output_dir: str = None,
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        workers: int = 5,
        writer: bool = True,
        sleep: int = 0,
        jitter: int = 0,
        *args,
        **kwargs,
    ):
        """Initialize an Enuermator instance.

        Note:
            All arguments, besides loop, are optional so that the Enumerator
            instance can be used to re-run the run() method multiple times
            against multiple domains/user lists without requiring a new instance
            or class level var modifications.

        Arguments:
            <required>
            loop: asyncio event loop
            <optional>
            module: enumeration module to run
            domain: domain to enumerate users against
            output_dir: directory to write results to
            timeout: http request timeout
            proxy: http request proxy
            workers: thread pool worker rate
            writer: toggle writing to output files
            sleep: throttle http requests
            jitter: randomize throttle

        Raises:
            ValueError: if no output directory provided when output writing
              is enabled
        """
        self._modules = {
            "autodiscover": None,  # self._autodiscover,  # DISABLED
            "activesync": self._activesync,
            "onedrive": self._onedrive,
            "office": self._office,
            "oauth2": self._oauth2,
        }

        if writer and not output_dir:
            raise ValueError("Missing 1 required argument: 'output_dir'")

        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.loop = loop
        self.module = module
        self.domain = domain
        self.timeout = timeout
        self.proxies = proxy
        self.sleep = sleep
        self.jitter = jitter
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

        # Initialize writers
        self.writer = writer
        if self.writer:
            self.found_idp = False  # Init bool for IDP accounts
            self.idp_writer = ThreadWriter(DefaultFiles.ENUM_IDP, output_dir)
            self.valid_writer = ThreadWriter(DefaultFiles.ENUM_FILE, output_dir)
            self.tested_writer = ThreadWriter(DefaultFiles.ENUM_TESTED, output_dir)

    def shutdown(self, key: bool = False):
        """Custom method to handle exitting multi-threaded tasking.

        Arguments:
            key: identify if we are shutting down normally or via a
              caught signal
        """
        msg = "\n\n[ ! ] CTRL-C caught." if key else "\n"
        if self.writer:
            msg += f"\n[ * ] Valid accounts can be found at: '{self.valid_writer.output_file}'"
            if self.found_idp:
                msg += f"\n[ * ] Accounts in different Identity Providers can be found at: '{self.idp_writer.output_file}'"
            msg += f"\n[ * ] All enumerated accounts can be found at: '{self.tested_writer.output_file}'\n"

        print(Defaults.ERASE_LINE, end="\r")
        logging.info(msg)

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit

        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait: None

        # Close the open file handles
        if self.writer:
            self.idp_writer.close()
            self.valid_writer.close()
            self.tested_writer.close()

    def get_modules(self):
        """Return the list of module names."""
        return self._modules.keys()

    # =============================
    # == -- ActiveSync MODULE -- ==
    # =============================

    def _activesync(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using Microsoft Server ActiveSync
        Original enumeration via: https://bitbucket.org/grimhacker/office365userenum/

        Arguments:
            <required>
            domain: domain to enumerate against
            user: username for enumeration request
            <optional>
            password: password for enumeration request

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab external headers from defaults.py and add special header
            # for ActiveSync
            headers = Defaults.HTTP_HEADERS
            headers["MS-ASProtocolVersion"] = "14.0"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            auth = HTTPBasicAuth(email, password)
            url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
            response = self._send_request(
                "options",
                url,
                auth=auth,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            status = response.status_code
            if status == 200:
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                logging.info(f"[{text_colors.green}VALID{text_colors.reset}] {email}")

            # Note: After the new MS updates, it appears that invalid users return a
            #       403 Forbidden while valid users appear to respond with a
            #       401 Unauthorized with a WWW-Authenticate response header that
            #       indicates Basic Auth negotiation was started
            elif status == 401 and "WWW-Authenticate" in response.headers.keys():
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                logging.info(f"[{text_colors.green}VALID{text_colors.reset}] {email}")

            # Note: Since invalid user's are now identified via 403 responses, we can
            #       just default all 403/404/etc. as invalid users
            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    # ===========================
    # == -- OneDrive MODULE -- ==
    # ===========================

    def _onedrive(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using One Drive
        https://github.com/nyxgeek/onedrive_user_enum/blob/master/onedrive_enum.py
        https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/

        Arguments:
            <required>
            domain: domain to enumerate against
            user: username for enumeration request
            <optional>
            password: password for enumeration request

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Remove email format from user if present
            orig_user = user
            user = user.split("@")[0]

            # Write the tested user
            tested = f"{orig_user} -> {user}" if user != orig_user else user
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Collect the pieces to build the One Drive URL
            domain_array = domain.split(".")

            domain = domain_array[0]  # Collect the domain
            tenant = domain  # Use domain as tenant
            tld = domain_array[-1]  # Grab the TLD
            # Replace any `.` with `_` for use in the URL
            fmt_user = user.replace(".", "_")

            url = "https://{TENANT}-my.sharepoint.com/personal/{USERNAME}_{DOMAIN}_{TLD}/_layouts/15/onedrive.aspx".format(
                TENANT=tenant,
                USERNAME=fmt_user,
                DOMAIN=domain,
                TLD=tld,
            )
            response = self._send_request(
                "get",
                url,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            # It appears that valid browser User-Agents will return a 302 redirect
            # instead of 401/403 on valid accounts
            status = response.status_code
            if status in [302, 401, 403]:
                if self.writer:
                    self.valid_writer.write(user)
                self.VALID_ACCOUNTS.append(user)
                logging.info(f"[{text_colors.green}VALID{text_colors.reset}] {user}")

            # Since 404 responses are invalid and everything else is considered
            # 'unknown', we will just handle them all as 'invalid'
            else:  # elif status == 404:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] " f"{user}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    # =============================
    # == -- Office.com MODULE -- ==
    # =============================

    def _pre_office(self):
        """
        Pre-handling of Office.com enumeration
        Collect and build the correct header and parameter data to perform
        user enumeration against office.com
        https://github.com/gremwell/o365enum/blob/master/o365enum.py
        """

        # Request the base domain to collect the `client_id`
        response = self._send_request(
            "get",
            "https://www.office.com",
            proxies=self.proxies,
            timeout=self.timeout,
            sleep=self.sleep,
            jitter=self.jitter,
        )
        client_id = re.findall(b'"appId":"([^"]*)"', response.content)

        # Request the /login page and follow redirects to collect the following params:
        #   `hpgid`, `hpgact`, `hpgrequestid`
        response = self._send_request(
            "get",
            "https://www.office.com/login?es=Click&ru=/&msafed=0",
            proxies=self.proxies,
            timeout=self.timeout,
            allow_redirects=True,
            sleep=self.sleep,
            jitter=self.jitter,
        )

        hpgid = re.findall(b'hpgid":([0-9]+),', response.content)
        hpgact = re.findall(b'hpgact":([0-9]+),', response.content)
        hpgrequestid = response.headers["x-ms-request-id"]

        # Grab external headers from defaults.py
        self.office_headers = Defaults.HTTP_HEADERS

        # Update headers
        self.office_headers["Referer"] = response.url
        self.office_headers["hpgrequestid"] = hpgrequestid
        self.office_headers["client-request-id"] = client_id[0]
        self.office_headers["hpgid"] = hpgid[0]
        self.office_headers["hpgact"] = hpgact[0]
        self.office_headers["Accept"] = "application/json"
        self.office_headers["Origin"] = "https://login.microsoftonline.com"

        # Build random canary token
        self.office_headers["canary"] = "".join(
            random.choice(
                string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
            )
            for _ in range(248)
        )

        # fmt: off
        # Build the Office request data
        self.office_data = {
            "originalRequest": re.findall(
                b'"sCtx":"([^"]*)"',
                response.content,
            )[0].decode("utf-8"),
            "isOtherIdpSupported": True,
            "isRemoteNGCSupported": True,
            "isAccessPassSupported": True,
            "checkPhones": False,
            "isCookieBannerShown": False,
            "isFidoSupported": False,
            "forceotclogin": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "isSignup": False,
            "federationFlags": 0,
        }
        # fmt: on

    def _office(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using Office.com
        https://github.com/gremwell/o365enum/blob/master/o365enum.py

        Arguments:
            <required>
            domain: domain to enumerate against
            user: username for enumeration request
            <optional>
            password: password for enumeration request

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab prebuilt office headers
            headers = self.office_headers

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            data = self.office_data
            data["username"] = email

            url = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
            response = self._send_request(
                "post",
                url,
                json=data,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            status = response.status_code
            body = response.json()

            if status == 200:
                if_exists_result = int(body["IfExistsResult"])

                # It appears that both 0 and 6 response codes indicate a valid user
                # whereas 5 indicates the use of a different identity provider -- let's
                # account for that.
                # https://www.redsiege.com/blog/2020/03/user-enumeration-part-2-microsoft-office-365/
                # https://warroom.rsmus.com/enumerating-emails-via-office-com/
                if if_exists_result in [0, 6]:
                    if self.writer:
                        self.valid_writer.write(email)
                    self.VALID_ACCOUNTS.append(email)
                    logging.info(
                        f"[{text_colors.green}VALID{text_colors.reset}] {email}"
                    )

                # This will not be added to our list of valid users as we want to avoid
                # hitting personal accounts
                elif if_exists_result == 5:
                    if self.writer:
                        if not self.found_idp:
                            self.found_idp = True
                        self.idp_writer.write(email)
                    logging.info(
                        f"[{text_colors.yellow}DIFFIDP{text_colors.reset}] {email}"
                    )
                    logging.debug(f"{email} -> Different Identity Provider")

                else:
                    print(
                        f"[{text_colors.red}INVALID{text_colors.reset}] "
                        f"{email}{' '*10}",
                        end="\r",
                    )

            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    # ===========================================
    # == -- Autodiscover MODULE -- DISABLED -- ==
    # ===========================================

    def _autodiscover(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using Microsoft Autodiscover
        Note: This method is dead based on recent MS updates. I am leaving this
              code here in case a new method of enumeration is identified via
              Autodiscover.
        Note: There may be a potential path of enumeration using Autodiscover by
              identifying responses that show 'Locked' based on the AAADSTS code
              (this appears to happen as a default response code to an invalid
              authentication attempt), but this would require an authentication attempt
              for each user.
        TODO: Test this
        https://github.com/Raikia/UhOh365

        Raises:
            NotImplementedError
        """
        raise NotImplementedError("This method is not currently implemented.")
        try:
            headers = Config.headers
            headers[
                "User-Agent"
            ] = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)"
            email = self.HELPER.check_email(user, domain)
            if self.writer:
                self.tested_writer.write(email)
            time.sleep(0.250)
            url = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{EMAIL}?Protocol=Autodiscoverv1".format(
                EMAIL=email
            )
            response = self._send_request(
                "get",
                url,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )
            status = response.status_code
            body = response.content
            # "X-MailboxGuid" in response.headers.keys()
            # This appears to not be a required header for valid accounts
            if status == 200:
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                logging.info(f"[{text_colors.green}VALID{text_colors.reset}] {email}")
            elif status == 302:
                if "outlook.office365.com" not in body:
                    if self.writer:
                        self.valid_writer.write(email)
                    self.VALID_ACCOUNTS.append(email)
                    logging.info(
                        f"[{text_colors.green}VALID{text_colors.reset}] {email}"
                    )
                else:
                    print(
                        f"[{text_colors.red}INVALID{text_colors.reset}] "
                        f"{email}{' '*10}",
                        end="\r",
                    )
            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}{' '*10}",
                    end="\r",
                )
        except Exception as e:
            logging.debug(e)
            pass

    # =========================
    # == -- oAuth2 MODULE -- ==
    # =========================

    def _oauth2(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users via Microsoft's oAuth2 endpoint
        https://github.com/Gerenios/AADInternals/blob/master/KillChain_utils.ps1#L112

        Arguments:
            <required>
            domain: domain to enumerate against
            user: username for enumeration request
            <optional>
            password: password for enumeration request

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab prebuilt office headers
            headers = Defaults.HTTP_HEADERS
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            randomGuid = uuid4()
            data = {
                "resource": randomGuid,
                "client_id": randomGuid,
                "grant_type": "password",
                "username": email,
                "password": password,
                "scope": "openid",
            }

            url = "https://login.microsoftonline.com/common/oauth2/token"
            response = self._send_request(
                "post",
                url,
                data=data,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            status = response.status_code
            body = response.json()
            if "error_codes" in body:
                error_codes = [f"AADSTS{code}" for code in body["error_codes"]]
            else:
                error_codes = None

            # Default to valid if 200 or 302
            if status == 200 or status == 302:
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                logging.info(f"[{text_colors.green}VALID{text_colors.reset}] {email}")

            elif error_codes:
                # User not found error is an invalid user
                if "AADSTS50034" in error_codes:
                    print(
                        f"[{text_colors.red}INVALID{text_colors.reset}] "
                        f"{email}{' '*10}",
                        end="\r",
                    )
                # Otherwise, valid user
                else:
                    if self.writer:
                        self.valid_writer.write(email)
                    self.VALID_ACCOUNTS.append(email)
                    logging.info(
                        f"[{text_colors.green}VALID{text_colors.reset}] {email}"
                    )

            # Unknown response -> invalid user
            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    async def run(
        self,
        userlist: List[str],
        password: str = "Password1",
        domain: str = None,
        module: str = None,
    ):
        """Asyncronously Send HTTP Requests to enumerate a list of users.
        This method's params override the class' level of params.

        Publicly accessible class method. To implement and run
        this method from another script:
        ```
            from o365spray.core import Enumerator
            loop = asyncio.get_event_loop()
            e = Enumerator(loop, writer=False)
            loop.run_until_complete(
                e.run(
                    userlist,
                    password,
                    domain,
                    module,
                )
            )
            loop.run_until_complete()
            loop.close()
            list_of_valid_users = e.VALID_ACCOUNTS
        ```

        Arguments:
            <required>
            userlist: list of users to enumerate
            <optional>
            password: password for modules that perform authentication
            domain: domain to enumerate users against
            module: enumeration module to run

        Raises:
            ValueError: if provided domain is empty/None or module does not
              exist
        """
        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain for user enumeration: '{domain}'")

        module = module or self.module
        if module not in self._modules.keys():
            raise ValueError(f"Invalid user enumeration module name: '{module}'")

        # Handle NotImplementedError exception handling here to avoid async
        # weirdness or relying on return_when of the asyncio.wait() method
        # since we want to pass through generic exceptions on run
        module_f = self._modules[module]
        if module_f == None:
            raise NotImplementedError("This module is not currently implemented.")

        # Build office module header/param data
        if module == "office":
            self._pre_office()

        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor,
                partial(
                    module_f,
                    domain=domain,
                    user=user,
                    password=password,
                ),
            )
            for user in userlist
        ]

        if blocking_tasks:
            await asyncio.wait(blocking_tasks)
