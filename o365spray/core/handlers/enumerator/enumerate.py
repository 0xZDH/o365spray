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


def enumerate(args: argparse.Namespace, output_dir: str) -> object:
    """Run user enumeration against a given domain.

    Arguments:
        args: namespace containing command line arguments
        output_dir: name of output directory to write results to

    Returns:
        initialized Enumerator module instance

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
        userlist += Helper.get_list_from_file(args.userfile)

    logging.info(f"Running user enumeration against {len(userlist)} potential users")

    # Attempt to import the defined module
    module = f"o365spray.core.handlers.enumerator.modules.{args.enum_module}"
    module_class = f"EnumerateModule_{args.enum_module}"

    try:
        Enumerator = getattr(importlib.import_module(module), module_class)
    except Exception as e:
        logging.error(f"ERROR: Invalid module\n{e}")
        return None

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
