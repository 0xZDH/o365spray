#!/usr/bin/env python3

import logging
import time
import requests  # type: ignore
import urllib3  # type: ignore
from random import randint
from typing import (
    Any,
    Dict,
    List,
    Union,
)

from o365spray.core.utils import (
    Defaults,
    Helper,
)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseHandler(object):
    """Module Base"""

    def __init__(
        self,
        useragents: List[str] = None,
        *args,
        **kwargs,
    ):
        """Initialize a module base handler.

        Note:
            This is to allow all modules to provide user agent
            lists for randomization easily.

        Arguments:
            <optional>
            useragents: list of user agents
        """
        self.useragents = useragents

    def _send_request(
        self,
        method: str,
        url: str,
        auth: object = None,
        json: dict = None,
        data: Union[str, Dict[Any, Any]] = None,
        headers: Dict[str, str] = Defaults.HTTP_HEADERS,
        proxies: Dict[str, str] = None,
        timeout: int = 25,
        verify: bool = False,
        allow_redirects: bool = False,
        sleep: int = 0,
        jitter: int = 0,
    ) -> requests.Response:
        """Template for HTTP requests.

        Arguments:
            method: http method
            url: url to send http request to
            auth: authentication  object (i.e. HTTPBasicAuth)
            json: json formatted data for post requests
            data: data for post requests
            headers: dictionary http headers
            proxies: request proxy server
            timeout: request timeout time
            verify: validadte HTTPS certificates
            allow_redirects: boolean to determine to follow redirects
            sleep: throttle requests
            jitter: randomize throttle

        Returns:
            response from http request

        Raises:
            ValueError: if http method provided is invalid
        """
        if method.lower() not in Defaults.HTTP_METHODS:
            raise ValueError(f"Invalid HTTP request method: {method}")

        # Sleep/Jitter to throttle subsequent request attempts
        if sleep > 0:
            throttle = sleep
            if jitter > 0:
                throttle = sleep + int(sleep * float(randint(1, jitter) / 100.0))
            logging.debug(f"Sleeping for {throttle} seconds before sending request.")
            time.sleep(throttle)

        # Retrieve random user agent and overwrite
        # the existing value
        if self.useragents:
            headers["User-Agent"] = Helper.get_random_element_from_list(self.useragents)

        return requests.request(
            method,
            url,
            auth=auth,
            data=data,
            json=json,
            headers=headers,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
        )
