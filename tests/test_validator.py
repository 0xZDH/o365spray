#!/usr/bin/env python3

import unittest
from o365spray.core import Validator  # type: ignore


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.v = Validator()

    def test_init(self):
        self.assertEqual(type(self.v), Validator)

    """
        We are disabling this unittest as we don't want to send
        validation traffic during unit testing.
    """
    # def test_validator(self):
    #     valid, adfs_url = self.v.validate("invalid_domain.unittest")
    #     self.assertEqual(valid, False)
    #     self.assertEqual(adfs_url, None)

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            _, _ = self.v.validate(None)

    def test_invalid_module(self):
        with self.assertRaises(ValueError):
            _, _ = self.v.validate(
                "invalid_domain.unittest",
                module="invalid",
            )

    def test_disabled_module(self):
        # `openid-config` module should raise NotImplementedError
        with self.assertRaises(NotImplementedError):
            _, _ = self.v.validate(
                "invalid_domain.unittest",
                module="openid-config",
            )


if __name__ == "__main__":
    unittest.main()
