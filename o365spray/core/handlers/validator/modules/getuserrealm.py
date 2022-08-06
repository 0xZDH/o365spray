#!/usr/bin/env python3

import html
import xml.etree.ElementTree as ET
from typing import Tuple
from o365spray.core.utils import (
    Defaults,
    Helper,
)
from o365spray.core.handlers.validator.modules.base import ValidatorBase


class ValidateModule_getuserrealm(ValidatorBase):
    """GetUserRealm Validation module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(ValidateModule_getuserrealm, self).__init__(*args, **kwargs)

    def _validate(self, domain: str) -> Tuple[bool, str]:
        """Validate O365 domain via GetUserRealm.

        Arguments:
            domain: domain to validate

        Returns:
            (if the domain is a valid O365 domain, ADFS AuthURL)
        """
        (valid, adfs_url) = (False, None)  # Defaults
        headers = Defaults.HTTP_HEADERS

        # Handle FireProx API URL
        if self.proxy_url:
            proxy_url = self.proxy_url.rstrip("/")
            url = f"{proxy_url}/getuserrealm.srf?login=user@{domain}&xml=1"

            # Update headers
            headers = Helper.fireprox_headers(headers)

        else:
            url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1"

        # Send request
        rsp = self._send_request(
            "get",
            url,
            headers=headers,
            proxies=self.proxies,
            timeout=self.timeout,
            sleep=self.sleep,
            jitter=self.jitter,
        )

        # Parse the XML response and find the NameSpaceType value in the
        # XML response
        xml = ET.fromstring(rsp.text)
        nst = xml.find("NameSpaceType").text

        if nst == "Federated":
            # Handle Federated realms differently than Managed
            # We will be directly spraying the federation servers via the
            # provided ADFS AuthURL
            valid = True
            adfs_url = html.unescape(xml.find("AuthURL").text)
        elif nst == "Managed":
            valid = True

        return (valid, adfs_url)
