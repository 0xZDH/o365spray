#!/usr/bin/env python3

import argparse
import importlib
import logging

from o365spray.core.utils import (
    Helper,
    text_colors,
)


def validate(args: argparse.Namespace) -> argparse.Namespace:
    """Validate a given domain is hosted by O365 and check if it is
    a Managed or Federated realm.

    Arguments:
        args: parsed command line arguments

    Returns:
        Updated command line arguments based on domain validation
    """
    logging.info(f"Validating: {args.domain}")

    # Attempt to import the defined module
    module = f"o365spray.core.handlers.validator.modules.{args.validate_module}"
    module_class = f"ValidateModule_{args.validate_module}"

    try:
        Validator = getattr(importlib.import_module(module), module_class)
    except Exception as e:
        logging.error(f"ERROR: Invalid module\n{e}")
        (args.enum, args.spray) = (False, False)
        return args

    v = Validator(
        timeout=args.timeout,
        proxy=args.proxy,
        sleep=args.sleep,
        jitter=args.jitter,
        useragents=args.useragents,
    )
    (valid, adfs) = v.validate(args.domain)

    # If the domain is invalid, notify the user, disable enum and spray
    # and return the args namespace
    if not valid:
        logging.info(
            f"[{text_colors.FAIL}FAILED{text_colors.ENDC}] "
            f"The following domain does not appear to be using O365: {args.domain}"
        )
        (args.enum, args.spray) = (False, False)
        return args

    # Notify the user of the results
    if adfs:
        logging.info(
            f"[{text_colors.WARNING}WARNING{text_colors.ENDC}] "
            f"The following domain appears to be using O365, but is Federated: {args.domain}"
            f"\n\t[!] --> ADFS AuthURL: {adfs}"
        )

    else:
        logging.info(
            f"[{text_colors.OKGREEN}VALID{text_colors.ENDC}] "
            f"The following domain appears to be using O365: {args.domain}"
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

        # Prompt the user if they would like to switch enumerations methods
        # if not using a valid ADFS option
        if args.enum and args.enum_module != "oauth2":
            logging.info("\n")  # Blank line
            prompt = (
                "[ ? ]\tSwitch to the oAuth2 module for user enumeration against a "
                "Federated Realm [Y/n] "
            )
            resp = Helper.prompt_question(prompt)
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
        if args.spray:
            if args.spray_module != "adfs":
                logging.info("\n")  # Blank line
                prompt = "[ ? ]\tSwitch to the ADFS module for password spraying [Y/n] "
                resp = Helper.prompt_question(prompt)
                if resp[0] == "y":
                    args.spray_module = "adfs"

    return args
