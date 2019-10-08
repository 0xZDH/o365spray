#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from .colors import text_colors


class Validator:
    """ This is to validate the target domain is using O365 """

    # getuserrealm seems to be considerably faster when identifying if a domain uses O365
    default_url   = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"
    secondary_url = "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration"

    def __init__(self, timeout=25, proxy=None, debug=False, secondary=False):
        self.url     = self.default_url
        self.timeout = timeout
        self.debug   = debug
        self.o365    = False
        self.proxy   = None if not proxy else {
            "http": proxy, "https": proxy
        }
        if secondary:
            self.url = self.secondary_url

    def validate(self, domain):
        try:
            rsp    = requests.get(self.url.format(DOMAIN=domain), timeout=self.timeout, proxies=self.proxy, verify=False)
            status = rsp.status_code

            if "getuserrealm" in self.url:
                xml = ET.fromstring(rsp.text)
                nst = xml.find('NameSpaceType').text

                if nst in ["Managed", "Federated"]:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, domain))
                    self.o365 = True

                else:
                    print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, domain))

            elif "openid-configuration" in self.url:
                if status == 200:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, domain))
                    self.o365 = True

                else:
                    print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, domain))

        except Exception as e:
            if self.debug: print("[DEBUG] %s" % e)
            pass