#!/usr/bin/env python3

import html
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Tuple, Union

from o365spray.core.handlers.base import BaseHandler  # type: ignore


class Validator(BaseHandler):
    """
    Validate whether or not a target domain is using O365
    and identify the Realm.
    """

    def __init__(
        self,
        domain: str = None,
        module: str = "getuserrealm",
        timeout: int = 25,
        proxy: Union[str, Dict[str, str]] = None,
        sleep: int = 0,
        jitter: int = 0,
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
            module: name of validator module to run
            proxy: http request proxy
            timeout: http request timeout
            sleep: throttle http requests
            jitter: randomize throttle
        """
        self._modules = {
            "getuserrealm": self._getuserrealm,
            "openid-config": self._openid_config,  # DISABLED
        }

        # If proxy server provided, build HTTP proxies object for
        # requests lib
        if isinstance(proxy, str):
            proxy = {"http": proxy, "https": proxy}

        self.domain = domain
        self.module = module
        self.proxies = proxy
        self.timeout = timeout
        self.sleep = sleep
        self.jitter = jitter

    def get_modules(self):
        """Return the list of module names."""
        return self._modules.keys()

    # ===============================
    # == -- GetUserRealm MODULE -- ==
    # ===============================

    def _getuserrealm(self, domain: str) -> Tuple[bool, str]:
        """Validate O365 domain via GetUserRealm.

        Arguments:
            domain: domain to validate

        Returns:
            (if the domain is a valid O365 domain, ADFS AuthURL)
        """
        (valid, adfs_url) = (False, None)  # Defaults

        url = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1".format(
            DOMAIN=domain
        )

        # Send request
        rsp = self._send_request(
            "get",
            url,
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

    # ============================================
    # == -- OpenID-Config MODULE -- DISABLED -- ==
    # ============================================

    def _openid_config(self, domain: str) -> Tuple[bool, str]:
        """Validate O365 domain via OpenID-Configuration.

        Note:
            We are going to unimplement this method since if a domain is
            valid, we have to run GetUserRealm anyway.

        Raises:
            NotImplementedError
        """
        raise NotImplementedError("This module is not currently implemented.")
        url = "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration".format(
            DOMAIN=domain
        )
        rsp = self._send_request(
            "get",
            url,
            proxies=self.proxies,
            timeout=self.timeout,
            sleep=self.sleep,
            jitter=self.jitter,
        )
        sts = rsp.status_code
        if sts == 200:
            return self._getuserrealm()
        return (False, None)

    def validate(
        self,
        domain: str = None,
        module: str = None,
    ) -> Tuple[bool, str]:
        """Perform domain validation against O365. This method's params
        override the class' level of params.

        Publicly accessible class method. To implement and run
        this method from another script:
        ```
            from o365spray.core import Validator
            v = Validator()
            valid, adfs_url = v.validate('domain.com')
        ```

        Arguments:
            domain: domain to validate
            module: name of validator module to run

        Raises:
            ValueError: if provided domain is empty/None or module does not
              exist
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        domain = domain or self.domain
        if not domain:
            raise ValueError(f"Invalid domain to validate: '{domain}'")

        module = module or self.module
        if module not in self._modules.keys():
            raise ValueError(f"Invalid validation module name: '{module}'")

        try:
            return self._modules[module](domain)
        except NotImplementedError as e:  # Catch disabled module(s)
            raise e
        except Exception as e:
            logging.debug(e)
            return (False, None)
