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

    def prompt_question(prompt):
        resp = str(input(prompt) or "Y").lower().strip()
        if resp[0] not in ['y', 'n']:
            return prompt_question(prompt)
        return resp

    def banner(self, args):
        BANNER  = "\n            *** O365 Spray ***            \n"
        BANNER += "\n>----------------------------------------<\n"

        _args = vars(args)
        for arg in _args:
            if _args[arg]:
                space = ' ' * (15 - len(arg))

                # Ignore enum/spray settings if not enabled
                if arg == 'enum_type' and not _args['enum'] or \
                   arg == 'spray_type' and not _args['spray']:
                    pass

                else:
                    BANNER += "\n   > %s%s:  %s" % (arg, space, str(_args[arg]))

                # Add data meanings
                if arg == 'count':
                    BANNER += " passwords/spray"

                if arg == 'lockout':
                    BANNER += " minutes"

                if arg == 'rate':
                    BANNER += " threads"

                if arg == 'safe':
                    BANNER += " locked accounts"

                if arg == 'timeout':
                    BANNER += " seconds"

        BANNER += "\n"
        BANNER += "\n>----------------------------------------<\n"

        print(BANNER)
