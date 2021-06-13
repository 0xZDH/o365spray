#!/usr/bin/env python3

import requests
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

        Returns:
            response from http request

        Raises:
            ValueError: if http method provided is invalid
        """
        if method.lower() not in Defaults.HTTP_METHODS:
            raise ValueError(f"Invalid HTTP request method: {method}")

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
