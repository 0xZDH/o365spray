#!/usr/bin/env python3

import asyncio
import unittest
from o365spray.core import Sprayer  # type: ignore


class TestSprayer(unittest.TestCase):

    loop = asyncio.get_event_loop()

    def setUp(self):
        self.s = Sprayer(self.loop, writer=False)

    def test_init(self):
        self.assertEqual(type(self.s), Sprayer)

    """
        We are disabling this unittest as we don't want to send
        password spraying traffic during unit testing.
    """
    # def test_sprayer(self):
    #     self.loop.run_until_complete(
    #         self.s.run(
    #             "password",
    #             domain="invalid_domain.unittest",
    #             module="activesync",
    #             userlist=["test"],
    #         )
    #     )
    #     self.loop.run_until_complete()
    #     self.assertEqual(s.VALID_CREDENTIALS, [])

    def test_invalid_userlist(self):
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.s.run(
                    "password",
                    domain="invalid_domain.unittest",
                    module="activesync",
                    userlist=None,
                )
            )
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.s.run(
                    "password",
                    domain="invalid_domain.unittest",
                    module="activesync",
                    userlist="single_user",  # Invalid type
                )
            )

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.s.run(
                    "password",
                    domain=None,
                    module="activesync",
                    userlist=["test"],
                )
            )

    def test_invalid_module(self):
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.s.run(
                    "password",
                    domain="invalid_domain.unittest",
                    module="invalid",
                    userlist=["test"],
                )
            )


if __name__ == "__main__":
    unittest.main()
