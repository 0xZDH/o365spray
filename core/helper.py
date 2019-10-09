#!/usr/bin/env python3

import time

class Helper:
    """ Helper functions """

    space = ' ' * 10

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
            _list = [line.strip() for line in f]
        return _list

    def check_last_chunk(self, sublist, full_list):
        """ Identify if the current list chunk is the last chunk """
        if sublist[-1] == full_list[-1]:
            return True
        return False

    def lockout_reset_wait(self, lockout):
        time.sleep(lockout * 60)

    def check_email(self, user, domain):
        if '@' in user:
            if domain != user.split('@')[-1]:
                user = "%s@%s" % (user.split('@')[0], domain)
        else:
            user = "%s@%s" % (user, domain)
        return user