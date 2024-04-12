#!/usr/bin/env python3

import logging
from typing import Dict

from o365spray.core.fire.fire import (
    FireProx,
    FireProxException,
)


AWS_REGIONS = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "eu-west-3",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "sa-east-1",
]

# o365spray module url map
MODULE_MAP = {
    # fmt: off
    "enum": {
        "autodiscover": "https://outlook.office365.com/",
        "autologon":    "https://autologon.microsoftazuread-sso.com/",
        "oauth2":       "https://login.microsoftonline.com/",
        "office":       "https://login.microsoftonline.com/",
        "rst":          "https://login.microsoftonline.com/",
    },
    "spray": {
        "autologon":    "https://autologon.microsoftazuread-sso.com/",
        "oauth2":       "https://login.microsoftonline.com/",
        "reporting":    "https://reports.office365.com/",

        # Disabled modules
        # "activesync":   "https://outlook.office365.com/",
        # "autodiscover": "https://autodiscover-s.outlook.com/",
        # "rst":          "https://login.microsoftonline.com/",
    },
    "not_implemented": [
        "onedrive",
        "adfs",

        # Disabled modules
        "activesync",
        "autodiscover",
        "rst",
    ]
    # fmt: on
}


def get_module_url(module: str, module_type: str) -> str:
    """Get the base url for a given module

    :param module: module name
    :param module_type: module type (enum, spray)
    :returns: module base url
    """
    if module_type not in ["enum", "spray"]:
        raise FireProxException(f"Invalid module type: {module_type}")

    if module_type == "enum":
        try:
            return MODULE_MAP["enum"][module]

        except KeyError:
            if module in MODULE_MAP["not_implemented"]:
                raise NotImplementedError(f"Module not implemented with FireProx: {module}")  # fmt: skip

            else:
                raise FireProxException(f"Invalid module: {module}")

    elif module_type == "spray":
        try:
            return MODULE_MAP["spray"][module]

        except KeyError:
            if module in MODULE_MAP["not_implemented"]:
                raise NotImplementedError(f"Module not implemented with FireProx: {module}")  # fmt: skip

            else:
                raise FireProxException(f"Invalid module: {module}")


def list_api(
    profile_name: str = None,
    access_key: str = None,
    secret_access_key: str = None,
    session_token: str = None,
    region: str = None,
    *args,
    **kwargs,
):
    """List all AWS API Gateways

    :param profile_name: aws profile name to store/retrieve credentials
    :param access_key: aws access key
    :param secret_access_key: aws secret access key
    :param session_token: aws session token
    :param region: aws region
    """
    fp = FireProx(
        profile_name=profile_name,
        access_key=access_key,
        secret_access_key=secret_access_key,
        session_token=session_token,
        region=region,
    )
    items = fp.list_api()

    logging.info("FireProx APIs:")
    for item in items:
        print(f"\t{item}")


def create_api(
    url: str,
    profile_name: str = None,
    access_key: str = None,
    secret_access_key: str = None,
    session_token: str = None,
    region: str = None,
    *args,
    **kwargs,
) -> Dict[str, str]:
    """Create an AWS API Gateway

    :param url: target url to create proxy for
    :param profile_name: aws profile name to store/retrieve credentials
    :param access_key: aws access key
    :param secret_access_key: aws secret access key
    :param session_token: aws session token
    :param region: aws region
    :returns: gateway id and url
    """
    fp = FireProx(
        url=url,
        profile_name=profile_name,
        access_key=access_key,
        secret_access_key=secret_access_key,
        session_token=session_token,
        region=region,
    )
    resource_id, proxy_url = fp.create_api(url=url)

    logging.info(f"FireProx ID: {resource_id}")
    logging.info(f"Proxy URL:   {proxy_url}")

    return {"api_gateway_id": resource_id, "proxy_url": proxy_url}


def destroy_api(
    api_id: str,
    profile_name: str = None,
    access_key: str = None,
    secret_access_key: str = None,
    session_token: str = None,
    *args,
    **kwargs,
):
    """Destroy a single AWS API Gateway instance based on ID

    :param api_id: fireprox api instance id
    :param profile_name: aws profile name to store/retrieve credentials
    :param access_key: aws access key
    :param secret_access_key: aws secret access key
    :param session_token: aws session token
    """
    for region in AWS_REGIONS:
        fp = FireProx(
            profile_name=profile_name,
            access_key=access_key,
            secret_access_key=secret_access_key,
            session_token=session_token,
            region=region,
        )
        active_apis = fp.list_api()

        for api in active_apis:
            if api["id"] == api_id:
                logging.info(f"Destroying FireProx API: '{api_id}'")
                fp.delete_api(api_id)
                return

    logging.error("FireProx API not found - could not destroy")


def destroy_all_apis(
    profile_name: str = None,
    access_key: str = None,
    secret_access_key: str = None,
    session_token: str = None,
    *args,
    **kwargs,
):
    """Clear all AWS API Gateway instances

    :param profile_name: aws profile name to store/retrieve credentials
    :param access_key: aws access key
    :param secret_access_key: aws secret access key
    :param session_token: aws session token
    """
    clear_count = 0

    for region in AWS_REGIONS:
        fp = FireProx(
            profile_name=profile_name,
            access_key=access_key,
            secret_access_key=secret_access_key,
            session_token=session_token,
            region=region,
        )
        active_apis = fp.list_api()

        logging.debug(f"Region: {region} - {len(active_apis)} APIs")

        for api in active_apis:
            if "fireprox" in api["name"]:
                logging.info(f"Deleting FireProx API: {api['name']} ({api['id']})")

                fp.delete_api(api["id"])
                clear_count += 1

    logging.info(f"FireProx APIs removed: {clear_count}")
