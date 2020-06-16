#!/usr/bin/env python3

# This only sends a single request so we can leave it using the requests function and avoid asyncio
import html
import requests
import xml.etree.ElementTree as ET
from core.utils.colors import text_colors
from core.utils.config import *


class Validator:
    """ This is to validate the target domain is using O365 """

    def __init__(self, args):
        self.args  = args
        self.proxy = None if not args.proxy else {
            "http": args.proxy, "https": args.proxy
        }
        # Validation Modules
        self._modules = {
            'getuserrealm':  self._getuserrealm,
            'openid-config': self._openid_config
        }


    def _send_request(self, url):
        return requests.get(  # Send HTTP request to validate domain
            url,
            headers=Config.headers,
            timeout=self.args.timeout,
            proxies=self.proxy,
            verify=False
        )


    """ Validate O365 domain via: GetUserRealm """
    def _getuserrealm(self):
        url = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"
        rsp = self._send_request(
            url.format(
                DOMAIN=self.args.domain
            )
        )

        xml     = ET.fromstring(rsp.text)
        nst     = xml.find('NameSpaceType').text
        authurl = xml.find('AuthURL').text

        if nst == "Managed":
            print("[%sVALID%s]\t\tThe following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.args.domain))
            return True

        # TODO: For the time being, we will just warn the user of federation and display the ADFS URL
        #       For the next iteration, add an ADFS password spraying module to allow users to dynamically
        #       switch to ADFS spraying instead of targeting MS API's
        elif nst == "Federated":
            print("[%sWARN%s]\t\tThe following domain is using O365, but is Federated: %s" % (text_colors.yellow, text_colors.reset, self.args.domain))
            print("\t\tAuthUrl: %s" % html.unescape(authurl))
            return False

        else:
            print("[%sFAILED%s]\tThe following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.args.domain))
            return False


    """ Validate O365 domain via: OpenID-Configuration """
    def _openid_config(self):
        url = "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration"
        rsp = self._send_request(
            url.format(
                DOMAIN=self.args.domain
            )
        )
        status = rsp.status_code

        # If the domain uses Office 365, let's check the user realm to identify Managed vs. Federated
        if status == 200:
            return self._getuserrealm()

        else:
            print("[%sFAILED%s]\tThe following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.args.domain))
            return False


    """ Perform domain validation against O365 """
    def validate(self):
        try:
            return self._modules[self.args.validate_type]()

        except Exception as e:
            if self.args.debug: print("[DEBUG]\t\t%s" % e)
            return False