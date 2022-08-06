#!/usr/bin/env python3

import urllib3  # type: ignore
import logging
from typing import (
    Dict,
    Tuple,
    Union,
)
from o365spray.core.handlers.base import BaseHandler  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ValidatorBase(BaseHandler):
    """
    Validate whether or not a target domain is using O365
    and identify the Realm.
    """

    def __init__(
        self,
        domain: str = None,
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        sleep: int = 0,
        jitter: int = 0,
        proxy_url: str = None,
        *args,
        **kwargs,
    ):
        """Initialize a Validator instance.

        Note:
            All arguments are optional so that the Validator instance
            can be used to re-run the validate() method multiple times
            against multiple domains without requiring a new instance
            or class level var modifications.

        Arguments:
            domain: domain to validate
            proxy: http request proxy
            timeout: http request timeout
            sleep: throttle http requests
            jitter: randomize throttle
            proxy_url: fireprox api url
        """
        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.domain = domain
        self.proxies = proxy
        self.timeout = timeout
        self.sleep = sleep
        self.jitter = jitter
        self.proxy_url = proxy_url

    def validate(
        self,
        domain: str = None,
    ) -> Tuple[bool, str]:
        """Perform domain validation against O365. This method's params
        override the class' level of params.

        Arguments:
            domain: domain to validate

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain to validate: '{domain}'")

        try:
            return self._validate(domain)
        except NotImplementedError as e:
            raise e
        except Exception as e:
            logging.debug(e)
            return (False, None)

    def _validate(self, domain: str) -> Tuple[bool, str]:
        """Parent implementation of module child method"""
        raise NotImplementedError("Must override _validate")
