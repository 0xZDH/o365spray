#!/usr/bin/env python3

import time
import logging
import requests
from random import randint
from typing import Dict, Any, Union

from o365spray.core import Defaults  # type: ignore


class BaseHandler(object):
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
            logging.debug(f"Sleeping for {sleep} seconds before sending request.")
            time.sleep(throttle)

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
