#!/usr/bin/env python3

import sys
import time
import argparse
from typing import (
    Any,
    List,
    Dict,
    Union,
)
from datetime import (
    datetime,
    timedelta,
)


class Helper:
    """Helper functions"""

    space = " " * 20

    @classmethod
    def write_data(
        cls,
        creds: Union[List[str], Dict[str, str]],
        file_: str,
        append: bool = True,
    ):
        """Write a given list of cred data to a specified file.

        Arguments:
            creds: data to write (if a dict, format key:value)
            file_: name of output file
            append: determine if we should write new file or append
        """
        mode = "a" if append else "w"
        if len(creds) > 0:
            if type(creds) == dict:
                creds = [f"{k}:{v}" for k, v in creds.items()]
            with open(file_, mode) as f:
                for account in creds:
                    f.write(f"{account}\n")

    @classmethod
    def get_chunks_from_list(
        cls,
        list_: List[Any],
        n: int,
    ) -> List[Any]:
        """Yield chunks of a given size, N, from a provided list.

        Arguments:
            list_: original list to chunk
            n: size of list segments

        Yields:
            list segment
        """
        for i in range(0, len(list_), n):
            yield list_[i : i + n]

    @classmethod
    def get_list_from_file(
        cls,
        file_: str,
    ) -> List[Any]:
        """Read a file's lines into a list.

        Arguments:
            file_: file to read into a list

        Returns:
            list of file lines
        """
        with open(file_, "r") as f:
            list_ = [line.strip() for line in f if line.strip() not in [None, ""]]
        return list_

    @classmethod
    def get_max_dict_elem(
        cls,
        dict_: Dict[str, List[str]],
    ) -> int:
        """Identify the largest list of values in a given
        dictionary.

        Arguments:
            dict_: dictionary to iterate over

        Returns:
            length of largest list of values
        """
        # Account for an empty dict_
        if not dict_:
            return 0
        max_ = max(dict_, key=lambda k: len(dict_[k]))
        return len(dict_[max_])

    @classmethod
    def get_paired_dict_from_file(
        cls,
        file_: str,
    ) -> List[Any]:
        """Read the paired username:password combinations from a
        file into an organized dict object.

        Arguments:
            file_: file to read into a list

        Returns:
            dict of {username: [passwords]}
        """
        with open(file_, "r") as f:
            list_ = [line.strip() for line in f if line.strip() not in [None, ""]]
        dict_ = {}
        for line in list_:
            try:
                (username, password) = line.split(":", 1)
                if username not in dict_.keys():
                    dict_[username] = []
                dict_[username].append(password)
            except:
                pass
        return dict_

    @classmethod
    def check_last_chunk(
        cls,
        sublist: List[Any],
        full_list: List[Any],
    ) -> bool:
        """Identify if the current list chunk is the last chunk.
        This assumes the full_list was uniqued prior to chunking.

        Arguments:
            sublist: sublist to compare to full_list
            full_list: complete list to check if sublist is in

        Returns:
            boolean if last chunk
        """
        if sublist[-1] == full_list[-1]:
            return True
        return False

    @classmethod
    def lockout_reset_wait(cls, lockout: Union[int, float]):
        """Print a lockout timer to the screen.
        Reference: https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/time.py

        Arguments:
            lockout: lockout time in minutes
        """
        delay = timedelta(hours=0, minutes=lockout, seconds=0)
        sys.stdout.write("\n\n")
        for remaining in range(int(delay.total_seconds()), 0, -1):
            sys.stdout.write(f"\r[*] Next spray in: {timedelta(seconds=remaining - 1)}")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\n\n")

    @classmethod
    def check_email(cls, user: str, domain: str) -> str:
        """Check if the given username is an email. If not, convert
        to an email address with the given doamin.

        Arguments:
            user: username to check for email format
            domain: domain to convert username to email format

        Returns:
            email address
        """
        if "@" in user:
            if domain != user.split("@")[-1]:
                user = "%s@%s" % (user.split("@")[0], domain)
        else:
            user = "%s@%s" % (user, domain)
        return user

    @classmethod
    def prompt_question(cls, prompt: str) -> str:
        """Prompt a user with a given question.

        Arguments:
            prompt: question to display to the user

        Returns:
            user response
        """
        resp = str(input(prompt) or "Y").lower().strip()
        if resp[0] not in ["y", "n"]:
            return prompt_question(prompt)  # type: ignore
        return resp

    @classmethod
    def banner(cls, args: argparse.Namespace, version: str):
        """Build a tool banner based on provided command line args.

        Arguments:
            args: populated argparse namespace
            version: tool version
        """
        BANNER = "\n            *** O365 Spray ***            \n"
        BANNER += "\n>----------------------------------------<\n"

        # Add version
        space = " " * (15 - len("version"))
        BANNER += "\n   > version%s:  %s" % (space, version)

        _args = vars(args)
        for arg in _args:
            if _args[arg]:

                # Handle conditions to not show certain data
                # 1) Don't show `rate` if both enum and spray are disabled or
                #    the user specified validation only
                if ((not args.enum and not args.spray) or args.validate) and (
                    arg == "rate"
                ):
                    continue
                # 2) Don't show `enum_module` if enum is disabled
                if not args.enum and arg == "enum_module":
                    continue
                # 3) Don't show the following if spray is disabled:
                #    spray_module, count, lockout, safe
                if not args.spray and (
                    arg == "spray_module"
                    or arg == "count"
                    or arg == "lockout"
                    or arg == "safe"
                ):
                    continue

                space = " " * (15 - len(arg))

                BANNER += "\n   > %s%s:  %s" % (arg, space, str(_args[arg]))

                # Add data meanings
                if arg == "count":
                    BANNER += " passwords/spray"

                if arg == "lockout":
                    BANNER += " minutes"

                if arg == "rate":
                    BANNER += " threads"

                if arg == "safe":
                    BANNER += " locked accounts"

                if arg == "timeout":
                    BANNER += " seconds"

        # Add timestamp for start of spray
        space = " " * (15 - len("start"))
        start_t = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
        BANNER += "\n   > start%s:  %s" % (space, start_t)

        BANNER += "\n"
        BANNER += "\n>----------------------------------------<\n"

        print(BANNER)
