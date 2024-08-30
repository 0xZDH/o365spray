#!/usr/bin/env python3

from datetime import datetime
from pathlib import Path
from time import time


class ThreadWriter(object):
    """Custom class to write data to a file accross threads"""

    def __init__(self, file_: str, out_dir: str):
        """Initialize a ThreadWriter instance.

        Arguments:
            file_: name of file to write to
            out_dir: name of directory to write file to

        Raises:
            ValueError: if directory does not exist
        """
        if not Path(out_dir).is_dir():
            raise ValueError(f"Invalid output directory: {out_dir}")
        self.output_file = f"{out_dir}{file_}"
        self.out_file = open(self.output_file, "a")

    def write(self, data: str):
        """Write data to file

        Arguments:
            data: data to write to file
        """
        ts = datetime.fromtimestamp(time()).strftime("%Y-%m-%d %H:%M:%S")
        self.out_file.write(f"[{ts}] {data}\n")

    def flush(self):
        """Flush the file buffer"""
        self.out_file.flush()

    def close(self):
        """Close the file handle"""
        self.out_file.close()
