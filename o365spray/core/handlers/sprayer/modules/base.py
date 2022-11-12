#!/usr/bin/env python3

import logging
import urllib3  # type: ignore
import asyncio
import concurrent.futures
import concurrent.futures.thread
from typing import (
    List,
    Dict,
    Union,
)
from functools import partial
from itertools import cycle
from o365spray.core.handlers.base import BaseHandler
from o365spray.core.utils import (
    Defaults,
    DefaultFiles,
    Helper,
    ThreadWriter,
    text_colors,
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SprayerBase(BaseHandler):

    HELPER = Helper()  # Helper functions
    VALID_CREDENTIALS = []  # Valid credentials storage

    def __init__(
        self,
        loop: Defaults.EventLoop,
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
        proxy_url: str = None,
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
            proxy_url: fireprox api url

        Raises:
            ValueError: if no output directory provided when output writing
              is enabled
        """
        super().__init__(*args, **kwargs)

        if writer and not output_dir:
            raise ValueError("Missing 1 required argument: 'output_dir'")

        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.loop = loop
        self.userlist = userlist
        self.domain = domain
        self.timeout = timeout
        self.proxies = proxy
        self.locked_limit = lock_threshold
        self.adfs_url = adfs_url
        self.sleep = sleep
        self.jitter = jitter
        self.proxy_url = proxy_url
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

        # Internal exit handler
        self.exit = False

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
        code = None
        for c in Defaults.AADSTS_CODES.keys():
            if c in response:
                code = c
                break

        # Account for invalid credentials error code
        if code and code != "AADSTS50126":
            # Handle lockout tracking
            if code == "AADSTS50053":
                self.lockout += 1

            # These error codes occur via oAuth2 only after a valid
            # authentication has been processed
            # Also account for expired passwords which only trigger
            # after valid authentication
            if code in Defaults.VALID_AADSTS_CODES:
                tested = f"{email}:{password}"
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {email}:{password}"
                )

            else:
                err = Defaults.AADSTS_CODES[code][0]
                msg = Defaults.AADSTS_CODES[code][1]
                logging.info(
                    f"[{text_colors.FAIL}{err}{text_colors.ENDC}] "
                    f"{email}:{password} "
                    f"({msg}.)"
                )

            # Remove errored user from being sprayed again
            self.userlist.remove(user)

        else:
            print(
                f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] "
                f"{email}:{password}{' '*10}",
                end="\r",
            )

    async def run(
        self,
        password: Union[str, List[str]],
        domain: str = None,
        userlist: List[str] = None,
    ):
        """Asyncronously Send HTTP Requests to password spray a list of users.
        This method's params override the class' level of params.

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

        if isinstance(password, list):
            # Since we assume this is our --paired handling, we will also
            # assume that the user list and password list are the same
            # length
            creds = zip(self.userlist, password)
        else:
            # Assume the password is not an object like a dict or instance
            # and that a single string/int/value was passed
            creds = zip(self.userlist, cycle([password]))

        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor,
                partial(
                    self._spray,
                    domain=domain,
                    user=user,
                    password=passwd,
                ),
            )
            for user, passwd in creds
        ]

        if blocking_tasks:
            await asyncio.wait(blocking_tasks)

    def _spray(self, domain: str, user: str, password: str):
        """Parent implementation of module child method"""
        raise NotImplementedError("Must override _spray")
