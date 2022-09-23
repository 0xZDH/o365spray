#!/usr/bin/env python3

import re
import time
import logging
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)
from o365spray.core.handlers.enumerator.modules.base import EnumeratorBase


class EnumerateModule_onedrive(EnumeratorBase):
    """OneDrive Enumeration module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(EnumerateModule_onedrive, self).__init__(*args, **kwargs)

    def _enumerate(self, domain: str, user: str, password: str = "Password1"):
        """Enumerate users on Microsoft using One Drive

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
            # Remove email format from user if present
            orig_user = user
            user = user.split("@")[0]

            # Write the tested user
            tested = f"{orig_user} -> {user}" if user != orig_user else user
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Collect the pieces to build the One Drive URL
            domain_mod = re.sub("^https?://", "", domain)  # Strip the protocol
            domain_mod = domain_mod.split("/")[0]  # Remove the path
            domain_array = domain_mod.split(".")  # Split into domain/subdomain array

            # Assume the domain/subdomain is the tenant
            # i.e. tenant.onmicrosoft.com
            #      tenant.com
            tenant = domain_array[0]

            # Replace the `.` with `_` in the domain
            # and keep the TLD
            domain = "_".join(domain_array)

            # Replace any `.` with `_` for use in the URL
            fmt_user = user.replace(".", "_")

            # Grab default headers
            headers = Defaults.HTTP_HEADERS

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/personal/{fmt_user}_{domain}/_layouts/15/onedrive.aspx"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = f"https://{tenant}-my.sharepoint.com/personal/{fmt_user}_{domain}/_layouts/15/onedrive.aspx"

            response = self._send_request(
                "get",
                url,
                headers=headers,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )

            # It appears that valid browser User-Agents will return a 302 redirect
            # instead of 401/403 on valid accounts
            status = response.status_code
            if status in [302, 401, 403]:
                if self.writer:
                    self.valid_writer.write(user)
                self.VALID_ACCOUNTS.append(user)
                logging.info(f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {user}")

            # Since 404 responses are invalid and everything else is considered
            # 'unknown', we will just handle them all as 'invalid'
            else:  # elif status == 404:
                print(
                    f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] " f"{user}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass
