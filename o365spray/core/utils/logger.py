#!/usr/bin/env python3

import logging
from o365spray.core.utils.colors import text_colors as bcolors


class LoggingLevels:
    CRITICAL = f"{bcolors.FAIL}%s{bcolors.ENDC}" % "crit"
    WARNING = f"{bcolors.WARNING}%s{bcolors.ENDC}" % "warn"
    DEBUG = f"{bcolors.OKBLUE}%s{bcolors.ENDC}" % "debg"
    ERROR = f"{bcolors.FAIL}%s{bcolors.ENDC}" % "fail"
    INFO = f"{bcolors.OKGREEN}%s{bcolors.ENDC}" % "info"


def init_logger(debug: bool):
    """Initialize program logging"""
    if debug:
        logging_level = logging.DEBUG
        logging_format = (
            "[%(asctime)s] [%(levelname)-5s] %(filename)17s:%(lineno)-4s - %(message)s"
        )
    else:
        logging_level = logging.INFO
        logging_format = "[%(asctime)s] [%(levelname)-5s] %(message)s"

    logging.basicConfig(format=logging_format, level=logging_level)

    # Handle color output
    logging.addLevelName(logging.CRITICAL, LoggingLevels.CRITICAL)
    logging.addLevelName(logging.WARNING, LoggingLevels.WARNING)
    logging.addLevelName(logging.DEBUG, LoggingLevels.DEBUG)
    logging.addLevelName(logging.ERROR, LoggingLevels.ERROR)
    logging.addLevelName(logging.INFO, LoggingLevels.INFO)
