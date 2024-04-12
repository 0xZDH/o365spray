#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from random import randint

from o365spray import __version__
from o365spray.core.fire import helper as fire
from o365spray.core.handlers.enumerator import enumerate
from o365spray.core.handlers.sprayer import spray
from o365spray.core.handlers.validator import validate
from o365spray.core.utils import (
    Helper,
    init_logger,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "o365spray | Microsoft O365 User Enumerator and Password Sprayer"
            f" -- v{__version__}"
        )
    )

    target_args = parser.add_argument_group(title="Target")
    target_args.add_argument(
        "-d",
        "--domain",
        type=str,
        help=(
            "Target domain for validation, user enumeration, "
            "and/or password spraying."
        ),
    )

    # Type of action(s) to run
    action_args = parser.add_argument_group(title="Actions")
    action_args.add_argument(
        "--validate", action="store_true", help="Run domain validation only."
    )
    action_args.add_argument(  # Can be used with --spray
        "--enum", action="store_true", help="Run username enumeration."
    )
    action_args.add_argument(  # Can be used with --enum
        "--spray", action="store_true", help="Run password spraying."
    )

    # Username(s)/Password(s) for enum/spray
    credential_args = parser.add_argument_group(title="Credentials")
    credential_args.add_argument(
        "-u", "--username", type=str, help="Username(s) delimited using commas."
    )
    credential_args.add_argument(
        "-p", "--password", type=str, help="Password(s) delimited using commas."
    )
    credential_args.add_argument(
        "-U", "--userfile", type=str, help="File containing list of usernames."
    )
    credential_args.add_argument(
        "-P", "--passfile", type=str, help="File containing list of passwords."
    )
    credential_args.add_argument(
        "--paired",
        type=str,
        help="File containing list of credentials in username:password format.",
    )

    # Password spraying lockout policy
    spraying_args = parser.add_argument_group(title="Password Spraying Configuration")
    spraying_args.add_argument(
        "-c",
        "--count",
        type=int,
        default=1,
        help=(
            "Number of password attempts to run per user before resetting the "
            "lockout account timer. Default: 1"
        ),
    )
    spraying_args.add_argument(
        "-l",
        "--lockout",
        type=float,
        default=15.0,
        help="Lockout policy's reset time (in minutes). Default: 15 minutes",
    )

    # Validate/Spray/Enum action specifications
    module_args = parser.add_argument_group(title="Module Configuration")
    module_args.add_argument(
        "--validate-module",
        type=str.lower,
        default="getuserrealm",
        help="Specify which valiadtion module to run. Default: getuserrealm",
    )
    module_args.add_argument(
        "--enum-module",
        type=str.lower,
        default="oauth2",
        help="Specify which enumeration module to run. Default: office",
    )
    module_args.add_argument(
        "--spray-module",
        type=str.lower,
        default="oauth2",
        help="Specify which password spraying module to run. Default: oauth2",
    )
    module_args.add_argument(
        "--adfs-url",
        type=str,
        help="AuthURL of the target domain's ADFS login page for password spraying.",
    )

    # General scan specifications
    scan_args = parser.add_argument_group(title="Scan Configuration")
    scan_args.add_argument(
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
    scan_args.add_argument(
        "--jitter",
        type=int,
        default=0,
        choices=range(0, 101),
        metavar="[0-100]",
        help="Jitter extends --sleep period by percentage given (0-100). Default: 0",
    )
    scan_args.add_argument(
        "--rate",
        type=int,
        default=10,
        help=(
            "Number of concurrent connections (attempts) during enumeration and "
            "spraying. Default: 10"
        ),
    )
    scan_args.add_argument(
        "--poolsize",
        type=int,
        default=10000,
        help="Maximum size of the ThreadPoolExecutor. Default: 10000",
    )
    scan_args.add_argument(
        "--safe",
        type=int,
        default=10,
        help=(
            "Terminate password spraying run if `N` locked accounts are observed. "
            "Default: 10"
        ),
    )

    # HTTP configurations
    http_args = parser.add_argument_group(title="HTTP Configuration")
    http_args.add_argument(
        "--useragents",
        type=str,
        help="File containing list of user agents for randomization.",
    )
    http_args.add_argument(
        "--timeout",
        type=int,
        default=25,
        help="HTTP request timeout in seconds. Default: 25",
    )
    http_args.add_argument(
        "--proxy",
        type=str,
        help="HTTP/S proxy to pass traffic through (e.g. http://127.0.0.1:8080).",
    )
    http_args.add_argument(
        "--proxy-url",
        type=str,
        help="FireProx API URL.",
    )

    # Misc configurations
    output_args = parser.add_argument_group(title="Output Configuration")
    output_args.add_argument(
        "--output",
        type=str,
        help=(
            "Output directory for results and test case files. "
            "Default: current directory"
        ),
    )

    # FireProx configuration
    fp_args = parser.add_argument_group(title="Fireprox Configuration")
    fp_args.add_argument(
        "--profile-name",
        type=str,
        help="AWS Profile Name to store/retrieve credentials.",
    )
    fp_args.add_argument(
        "--access-key",
        type=str,
        help="AWS Access Key.",
    )
    fp_args.add_argument(
        "--secret-access-key",
        type=str,
        help="AWS Secret Access Key.",
    )
    fp_args.add_argument(
        "--session-token",
        type=str,
        help="AWS Session Token.",
    )
    fp_args.add_argument(
        "--region",
        type=str,
        choices=fire.AWS_REGIONS,
        help="AWS Region.",
    )

    # FireProx utilities
    fpu_args = parser.add_argument_group(title="Fireprox Utilities")
    fpu_args.add_argument(
        "--api-list",
        action="store_true",
        help="List all fireprox APIs.",
    )
    fpu_args.add_argument(
        "--api-destroy",
        type=str,
        help="Destroy single API instance, by API ID.",
    )
    # fpu_args.add_argument(
    #     "--api-destroy-all",
    #     action="store_true",
    #     help="Destroy all fireprox AWS APIs from every region (Warning: this is irreversible).",
    # )

    debug_args = parser.add_argument_group(title="Debug")
    debug_args.add_argument(
        "-v", "--version", action="store_true", help="Print the tool version."
    )
    debug_args.add_argument("--debug", action="store_true", help="Enable debug output.")
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

    # FireProx handling
    args.fireprox_args = None
    if (
        args.profile_name
        or args.access_key
        or args.secret_access_key
        or args.session_token
        or args.region
        or args.api_list
        or args.api_destroy
        # or args.api_destroy_all
    ):
        # Build initial fire.py argument handling
        args.fireprox_args = {
            "profile_name": args.profile_name,
            "access_key": args.access_key,
            "secret_access_key": args.secret_access_key,
            "session_token": args.session_token,
            "region": args.region,
            "api_id": args.api_destroy,
        }

        # Handle fire.py api callers
        if args.api_list:
            sys.exit(fire.list_api(**args.fireprox_args))

        if args.api_destroy:
            sys.exit(fire.destroy_api(**args.fireprox_args))

        # if args.api_destroy_all:
        #     sys.exit(fire.destroy_all_apis(**args.fireprox_args))

        # Handle fire.py conflicts
        if args.validate:
            parser.error("the validate module does not support fire.py handling")

        if args.proxy_url:
            parser.error("proxy url already provided, can not run fire.py")

        # Get the base url to proxy through FireProx based on module name
        enum_module_base_url = None
        if args.enum:
            enum_module_base_url = fire.get_module_url(args.enum_module, "enum")

        spray_module_base_url = None
        if args.spray:
            spray_module_base_url = fire.get_module_url(args.spray_module, "spray")

        # If enum and spray both enabled, make sure the module base urls are
        # the same to avoid conflicts (for now)
        if (
            enum_module_base_url
            and spray_module_base_url
            and (enum_module_base_url != spray_module_base_url)
        ):
            parser.error("can not use conflicting enum and spray modules with fire.py")

        # Add module URL to fire.py argument handling
        args.fireprox_args["url"] = enum_module_base_url or spray_module_base_url

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

    # Validate user agent file and load data set
    if args.useragents:
        if not Path(args.useragents).is_file():
            parser.error("invalid user agent file provided")

        else:
            args.useragents = Helper.get_list_from_file(args.useragents)

    # Handle sleep randomization
    if args.sleep == -1:
        args.sleep = randint(1, 120)

    if (args.enum or args.spray) and args.userfile:
        if not Path(args.userfile).is_file():
            parser.error("invalid username file provided")

    if args.spray and args.passfile:
        if not Path(args.passfile).is_file():
            parser.error("invalid password file provided")

    return args


def main():
    """Main entry point for o365spray"""

    # Parse command line arguments
    args = parse_args()

    # Initialize logging level and format
    init_logger(args.debug)

    start = time.time()

    # Print banner with config settings
    Helper.banner(args, __version__)

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
        if args.enum and args.enum_module != "oauth2":
            logging.info("Switching to oAuth2 module for user enumeration")
            args.enum_module = "oauth2"
        if args.spray and args.spray_module != "adfs":
            logging.info("Switching to ADFS module for password spraying")
            args.spray_module = "adfs"

    else:
        # Perform domain validation
        args = validate(args)

    # Handle fire.py api creation
    if args.fireprox_args and (args.enum or args.spray):
        api = fire.create_api(**args.fireprox_args)

        # Update args namespace
        args.proxy_url = api["proxy_url"]
        args.fireprox_args["api_id"] = api["api_gateway_id"]

    # Perform user enumeration
    if args.enum:
        enum = enumerate(args, output_directory)
    else:
        enum = None

    if args.spray:
        spray(args, output_directory, enum)

    # Handle internal creation/deletion with fire.py
    if args.fireprox_args and args.fireprox_args.get("api_id", None):
        fire.destroy_api(**args.fireprox_args)

    elapsed = time.time() - start
    logging.debug(f"o365spray executed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
