#!/usr/bin/env python3

# This only sends a single request so we can leave it using the requests function and avoid asyncio
import requests
import xml.etree.ElementTree as ET
from core.utils.colors import text_colors
from core.utils.config import *


class Validator:
    """ This is to validate the target domain is using O365 """

    def __init__(self, args):
        self.args  = args
        self.url   = msonline["url"]
        self.o365  = False
        self.proxy = None if not args.proxy else {
            "http": args.proxy, "https": args.proxy
        }
        if args.secondary or args.validate_secondary:
            self.url = msonline["url2"]

    def validate(self):
        try:
            rsp    = requests.get(self.url.format(DOMAIN=self.args.domain), headers=headers, timeout=self.args.timeout, proxies=self.proxy, verify=False)
            status = rsp.status_code

            if "getuserrealm" in self.url:
                xml = ET.fromstring(rsp.text)
                nst = xml.find('NameSpaceType').text

                if nst in ["Managed", "Federated"]:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.args.domain))
                    self.o365 = True

                else:
                    print("[%sFAILED%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.args.domain))

            elif "openid-configuration" in self.url:
                if status == 200:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.args.domain))
                    self.o365 = True

                else:
                    print("[%sFAILED%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.args.domain))

        except Exception as e:
            if self.args.debug: print("[DEBUG] %s" % e)
            pass