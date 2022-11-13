#!/usr/bin/env python3

import logging
import time

from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


class EnumerateModule_autodiscover(EnumeratorBase):
    """Autodiscover Enumeration module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(EnumerateModule_autodiscover, self).__init__(*args, **kwargs)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using Microsoft Autodiscover

        Note: It appears a potential path of enumeration using Autodiscover is by
              identifying responses that have the 'Vary' header.
              I am almost positive this is complete bullshit, but leaving here for now...

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
            # Add custom User-Agent to appear from outlook
            headers = Defaults.HTTP_HEADERS
            headers["User-Agent"] = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro)"  # fmt: skip

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{user} -> {email}" if user != email else email
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/autodiscover/autodiscover.json/v1.0/{email}?Protocol=Autodiscoverv1"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=Autodiscoverv1"

            response = self._send_request(
                "get",
                url,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            # If the 'Vary' header exists, assume valid
            if "Vary" in response.headers:
                if self.writer:
                    self.valid_writer.write(email)
                self.VALID_ACCOUNTS.append(email)
                logging.info(f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {email}")

            # Otherwise, invalid
            else:
                print(
                    f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] "
                    f"{email}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass
