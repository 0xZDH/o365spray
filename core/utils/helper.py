#!/usr/bin/env python3

import sys
import time
from datetime import timedelta

class Helper:
    """ Helper functions """

    space = ' ' * 20

    def write_data(self, creds, _file):
        if len(creds) > 0:
            if type(creds) == dict: creds = ['%s:%s' % (k, v) for k, v in creds.items()]
            with open(_file, 'a') as f:
                for account in creds:
                    f.write("%s\n" % account)

    def write_tested(self, creds, _file):
        if len(creds) > 0:
            if type(creds) == dict: creds = ['%s:%s' % (k, v) for k, v in creds.items()]
            with open(_file, 'w') as f:
                for account in creds:
                    f.write("%s\n" % account)

    def get_chunks_from_list(self, _list, n):
        for i in range(0, len(_list), n):
            yield _list[i:i + n]

    def get_list_from_file(self, _file):
        with open(_file, "r") as f:
            _list = [line.strip() for line in f if line.strip() not in [None, ""]]
        return _list

    def check_last_chunk(self, sublist, full_list):
        """ Identify if the current list chunk is the last chunk """
        if sublist[-1] == full_list[-1]:
            return True
        return False

    def lockout_reset_wait(self, lockout):
        # From: https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/core/utils/time.py
        delay = timedelta(
            hours=0,
            minutes=lockout,
            seconds=0
        )
        sys.stdout.write('\n\n')
        for remaining in range(int(delay.total_seconds()), 0, -1):
            sys.stdout.write(f"\r[*] Next spray in: {timedelta(seconds=remaining - 1)}")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write('\n\n')

    def check_email(self, user, domain):
        if '@' in user:
            if domain != user.split('@')[-1]:
                user = "%s@%s" % (user.split('@')[0], domain)
        else:
            user = "%s@%s" % (user, domain)
        return user

    def banner(self, args):
        BANNER = """
            *** O365 Spray ***

>----------------------------------------<
"""

        args = vars(args)
        for arg in args:
            if args[arg]:
                space = ' ' * (15 - len(arg))
                BANNER += "\n   > %s%s:  %s" % (arg, space, str(args[arg]))

        BANNER += "\n\n>----------------------------------------<\n"

        print(BANNER)
