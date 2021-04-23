#!/usr/bin/env python3

# This only sends a single request so we can leave it using the requests function and avoid asyncio
import html
import random
import time
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
        if self.args.sleep > 0:
            sleep = self.args.sleep
            if self.args.jitter > 0:
                sleep = sleep + int(sleep * float(random.randint(1, self.args.jitter) / 100.0))
            if self.args.debug: print(f"\n[DEBUG]\tSleeping for {sleep} seconds before sending request...")
            time.sleep(sleep)

        return requests.get(  # Send HTTP request to validate domain
            url,
            headers=Config.headers,
            timeout=self.args.timeout,
            proxies=self.proxy,
            verify=False
        )


    """ Perform domain validation against O365 """
    def validate(self):
        try:
            return self._modules[self.args.validate_type]()

        except Exception as e:
            if self.args.debug: print("[DEBUG]\t\t%s" % e)
            return (False,None)


    # ===============================
    # == -- GetUserRealm MODULE -- ==
    # ===============================

    """ Validate O365 domain via: GetUserRealm """
    def _getuserrealm(self):
        url = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"
        rsp = self._send_request(
            url.format(
                DOMAIN=self.args.domain
            )
        )

        xml = ET.fromstring(rsp.text)
        nst = xml.find('NameSpaceType').text

        if nst == "Managed":
            print("[%sVALID%s]\t\tThe following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.args.domain))
            return (True,None)

        # Handle Federated realms differently than Managed - Directly spray the federation servers
        elif nst == "Federated":
            authurl = html.unescape(xml.find('AuthURL').text)
            print("[%sWARN%s]\t\tThe following domain is using O365, but is Federated: %s" % (text_colors.yellow, text_colors.reset, self.args.domain))
            print("\t\tAuthUrl: %s" % authurl)
            return (True,authurl)

        else:
            print("[%sFAILED%s]\tThe following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.args.domain))
            return (False,None)


    # ================================
    # == -- OpenID-Config MODULE -- ==
    # ================================

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
            return (False,None)
