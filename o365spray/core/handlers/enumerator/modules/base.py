#!/usr/bin/env python3

import asyncio
import concurrent.futures
import concurrent.futures.thread
import logging
import urllib3  # type: ignore
from functools import partial
from typing import (
    Dict,
    List,
    Union,
)

from o365spray.core.handlers.base import BaseHandler
from o365spray.core.utils import (
    Defaults,
    DefaultFiles,
    Helper,
    ThreadWriter,
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EnumeratorBase(BaseHandler):
    """Perform user enumeration against Microsoft O365."""

    HELPER = Helper()  # Helper functions
    VALID_ACCOUNTS = []  # Valid accounts storage

    def __init__(
        self,
        loop: Defaults.EventLoop,
        domain: str = None,
        output_dir: str = None,
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        workers: int = 5,
        conlimit: int = 10000,
        writer: bool = True,
        sleep: int = 0,
        jitter: int = 0,
        proxy_url: str = None,
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
            domain: domain to enumerate users against
            output_dir: directory to write results to
            timeout: http request timeout
            proxy: http request proxy
            workers: thread pool worker rate
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
        self.domain = domain
        self.timeout = timeout
        self.proxies = proxy
        self.sleep = sleep
        self.jitter = jitter
        self.proxy_url = proxy_url
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        self.conlimit = conlimit

        # Internal exit handler
        self.exit = False

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

    def _consume_threads(self, threads: list, max_n: int):
        while len(threads) > max_n:
            done, _ = concurrent.futures.wait(
                threads,
                return_when=concurrent.futures.FIRST_COMPLETED
            )

            for t in done:
                t.result()
                del threads[t]

    async def run(
        self,
        userlist: List[str],
        password: str = "Password1",
        domain: str = None,
    ):
        """Asyncronously Send HTTP Requests to enumerate a list of users.
        This method's params override the class' level of params.

        Arguments:
            <required>
            userlist: list of users to enumerate
            <optional>
            password: password for modules that perform authentication
            domain: domain to enumerate users against

        Raises:
            ValueError: if provided domain is empty/None
        """
        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain for user enumeration: '{domain}'")

        threads = {}
        for user in userlist:
            future = self.executor.submit(
                self._enumerate, domain=domain, user=user, password=password
            )

            threads[future] = 1
            self._consume_threads(threads, self.conlimit)

        self._consume_threads(threads, 0)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Parent implementation of module child method"""
        raise NotImplementedError("Must override _enumerate")
