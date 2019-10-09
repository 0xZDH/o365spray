#!/usr/bin/env python3

import sys
import time
from datetime import datetime
from datetime import timedelta

class Helper:
    """ Helper functions """

    space = ' ' * 20

    def write_data(self, creds, _file):
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
        target  = datetime.now()
        one_sec = timedelta(seconds=1)
        for remaining in range(int(delay.total_seconds()), 0, -1):
            target += one_sec
            sys.stdout.write(f"\r[*] Next spray in: {timedelta(seconds=remaining - 1)}")
            sys.stdout.flush()
            duration = (target - datetime.now()).total_seconds()
            if duration > 0: time.sleep(duration)
        sys.stdout.write('\n')
        sys.stdout.flush()

    def check_email(self, user, domain):
        if '@' in user:
            if domain != user.split('@')[-1]:
                user = "%s@%s" % (user.split('@')[0], domain)
        else:
            user = "%s@%s" % (user, domain)
        return user