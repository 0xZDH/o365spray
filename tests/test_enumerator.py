#!/usr/bin/env python3

import asyncio
import unittest
from o365spray.core import Enumerator  # type: ignore


class TestEnumerator(unittest.TestCase):

    loop = asyncio.get_event_loop()

    def setUp(self):
        self.e = Enumerator(self.loop, writer=False)

    def test_init(self):
        self.assertEqual(type(self.e), Enumerator)

    """
        We are disabling this unittest as we don't want to send
        enumeration traffic during unit testing.
    """
    # def test_validator(self):
    #     self.loop.run_until_complete(
    #         self.e.run(
    #             ["test"],
    #             password="password1",
    #             domain="invalid_domain.unittest",
    #             module="office",
    #         )
    #     )
    #     self.loop.run_until_complete()
    #     self.assertEqual(e.VALID_ACCOUNTS, [])

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.e.run(
                    ["test"],
                    password="password1",
                    domain=None,
                    module="office",
                )
            )

    def test_invalid_module(self):
        with self.assertRaises(ValueError):
            self.loop.run_until_complete(
                self.e.run(
                    ["test"],
                    password="password1",
                    domain="invalid_domain.unittest",
                    module="invalid",
                )
            )

    def test_disabled_module(self):
        # `autodiscover` module should raise NotImplementedError
        with self.assertRaises(NotImplementedError):
            self.loop.run_until_complete(
                self.e.run(
                    ["test"],
                    password="password1",
                    domain="invalid_domain.unittest",
                    module="autodiscover",
                )
            )


if __name__ == "__main__":
    unittest.main()
