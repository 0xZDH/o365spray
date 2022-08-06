#!/usr/bin/env python3

import sys
from colorama import (  # type: ignore
    init,
    Fore,
)


# Init colorama to switch between Windows and Linux
if sys.platform == "win32":
    init(convert=True)


class text_colors:
    """Color codes for colorized terminal output"""

    HEADER = Fore.MAGENTA
    OKBLUE = Fore.BLUE
    OKCYAN = Fore.CYAN
    OKGREEN = Fore.GREEN
    WARNING = Fore.YELLOW
    FAIL = Fore.RED
    ENDC = Fore.RESET
