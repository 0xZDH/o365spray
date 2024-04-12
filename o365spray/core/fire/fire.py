#!/usr/bin/env python3
# Modified version of: https://github.com/ustayready/fireprox

import argparse
import boto3  # type: ignore
import configparser
import datetime
import logging
import os
import tldextract  # type: ignore
from typing import (
    List,
    Tuple,
)


class FireProxException(Exception):
    """Custom FireProx exception handler"""

    pass


class FireProx(object):
    """FireProx handler"""

    def __init__(
        self,
        url: str = None,
        profile_name: str = None,
        access_key: str = None,
        secret_access_key: str = None,
        session_token: str = None,
        region: str = None,
        api_id: str = None,
        *args,
        **kwargs,
    ):
        """Initialize FireProx

        :param url: url to proxy
        :param profile_name: aws profile name to store/retrieve credentials
        :param access_key: aws access key
        :param secret_access_key: aws secret access key
        :param session_token: aws session token
        :param region: aws region
        :param api_id: api id
        """
        # fmt: off
        self.url               = url
        self.profile_name      = profile_name
        self.access_key        = access_key
        self.secret_access_key = secret_access_key
        self.session_token     = session_token
        self.region            = region
        self.api_id            = api_id
        self.client            = None
        # fmt: on

        if self.access_key and self.secret_access_key:
            if not self.region:
                raise FireProxException("'region' required when using 'access_key' and 'secret_access_key'")  # fmt: skip

        if not self._load_credentials():
            raise FireProxException("Failed to load AWS credentials")

    def _try_instance_profile(self) -> bool:
        """Try instance profile credentials

        :returns: boolean if client session created
        """
        try:
            # Create a new boto3 low-level client
            if not self.region:
                self.client = boto3.client("apigateway")

            else:
                self.client = boto3.client("apigateway", region_name=self.region)

            # Attempt to get the client account and set the region
            # accordingly
            self.client.get_account()
            self.region = self.client._client_config.region_name

            return True

        except Exception as e:
            logging.error(f"AWS client exception: {e}")
            return False

    def _load_credentials(self) -> bool:
        """Load credentials from AWS config and credentials
        files if present

        :returns: boolean if credentials loaded
        """
        # If no access_key, secret_key, or profile_name provided -
        # try instance credentials
        if not any([self.access_key, self.secret_access_key, self.profile_name]):
            return self._try_instance_profile()

        # Read in AWS config/credentials files if they exist
        credentials = configparser.ConfigParser()
        credentials.read(os.path.expanduser("~/.aws/credentials"))

        config = configparser.ConfigParser()
        config.read(os.path.expanduser("~/.aws/config"))

        # If profile in files, try it, but flow through if it does not work
        config_profile_section = f"profile {self.profile_name}"
        if self.profile_name in credentials:
            if config_profile_section not in config:
                logging.error("Failed to parse aws configuration")
                logging.error(f"Missing section: '{self.profile_name}'")
                return False

            # Default region to us-east-1
            self.region = config[config_profile_section].get("region", "us-east-1")

            try:
                self.client = boto3.session.Session(profile_name=self.profile_name).client("apigateway")  # fmt: skip
                self.client.get_account()

                return True

            except:
                pass

        # Maybe had profile, maybe didn't
        if self.access_key and self.secret_access_key:
            try:
                self.client = boto3.client(
                    "apigateway",
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_access_key,
                    aws_session_token=self.session_token,
                    region_name=self.region,
                )
                self.client.get_account()
                self.region = self.client._client_config.region_name

                # Save/overwrite config if profile specified
                if self.profile_name:
                    if config_profile_section not in config:
                        config.add_section(config_profile_section)

                    config[config_profile_section]["region"] = self.region
                    with open(os.path.expanduser("~/.aws/config"), "w") as file:
                        config.write(file)

                    if self.profile_name not in credentials:
                        credentials.add_section(self.profile_name)

                    # fmt: off
                    credentials[self.profile_name]["aws_access_key_id"] = self.access_key
                    credentials[self.profile_name]["aws_secret_access_key"] = self.secret_access_key
                    # fmt: on

                    if self.session_token:
                        credentials[self.profile_name]["aws_session_token"] = self.session_token  # fmt: skip

                    else:
                        credentials.remove_option(self.profile_name, "aws_session_token")  # fmt: skip

                    with open(os.path.expanduser("~/.aws/credentials"), "w") as file:
                        credentials.write(file)

                return True

            except:
                return False

        else:
            return False

    def _get_template(self, url: str = None) -> bytes:
        """Create AWS instance template

        :param url: target url to create proxy for
        :returns: aws instance template
        """
        url = url or self.url

        url = url.rstrip("/")
        title = "fireprox_{}".format(tldextract.extract(url).domain)
        version_date = f"{datetime.datetime.now():%Y-%m-%dT%XZ}"

        template = """
        {
          "swagger": "2.0",
          "info": {
            "version": "_VERSION_DATE_",
            "title": "_TITLE_"
          },
          "basePath": "/",
          "schemes": [
            "https"
          ],
          "paths": {
            "/": {
              "get": {
                "parameters": [
                  {
                    "name": "proxy",
                    "in": "path",
                    "required": true,
                    "type": "string"
                  },
                  {
                    "name": "X-My-X-Forwarded-For",
                    "in": "header",
                    "required": false,
                    "type": "string"
                  }
                ],
                "responses": {},
                "x-amazon-apigateway-integration": {
                  "uri": "_URL_/",
                  "responses": {
                    "default": {
                      "statusCode": "200"
                    }
                  },
                  "requestParameters": {
                    "integration.request.path.proxy": "method.request.path.proxy",
                    "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
                  },
                  "passthroughBehavior": "when_no_match",
                  "httpMethod": "ANY",
                  "cacheNamespace": "irx7tm",
                  "cacheKeyParameters": [
                    "method.request.path.proxy"
                  ],
                  "type": "http_proxy"
                }
              }
            },
            "/{proxy+}": {
              "x-amazon-apigateway-any-method": {
                "produces": [
                  "application/json"
                ],
                "parameters": [
                  {
                    "name": "proxy",
                    "in": "path",
                    "required": true,
                    "type": "string"
                  },
                  {
                    "name": "X-My-X-Forwarded-For",
                    "in": "header",
                    "required": false,
                    "type": "string"
                  }
                ],
                "responses": {},
                "x-amazon-apigateway-integration": {
                  "uri": "_URL_/{proxy}",
                  "responses": {
                    "default": {
                      "statusCode": "200"
                    }
                  },
                  "requestParameters": {
                    "integration.request.path.proxy": "method.request.path.proxy",
                    "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
                  },
                  "passthroughBehavior": "when_no_match",
                  "httpMethod": "ANY",
                  "cacheNamespace": "irx7tm",
                  "cacheKeyParameters": [
                    "method.request.path.proxy"
                  ],
                  "type": "http_proxy"
                }
              }
            }
          }
        }
        """
        template = template.replace("_URL_", url)
        template = template.replace("_TITLE_", title)
        template = template.replace("_VERSION_DATE_", version_date)

        return str.encode(template)

    def _create_deployment(self, api_id: str) -> Tuple[str, str]:
        """Create application revision deployment

        :param api_id: fireprox instance id
        :returns: (resource_id, fireprox url)
        """
        response = self.client.create_deployment(
            restApiId=api_id,
            stageName="fireprox",
            stageDescription="FireProx Prod",
            description="FireProx Production Deployment",
        )

        resource_id = response["id"]
        url = f"https://{api_id}.execute-api.{self.region}.amazonaws.com/fireprox/"

        return (resource_id, url)

    def _get_resource(self, api_id: str) -> str:
        """Get resources for a given API instance

        :param api_id: fireprox instance id
        :returns: item id for fireprox resource
        """
        response = self.client.get_resources(restApiId=api_id)

        items = response["items"]
        for item in items:
            if item["path"] == "/{proxy+}":
                return item["id"]

        return None

    def _get_integration(self, api_id: str) -> str:
        """Get API instance integration settings

        :param api_id: fireprox instance id
        :returns: api url being proxied
        """
        resource_id = self._get_resource(api_id)

        response = self.client.get_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
        )

        return response["uri"]

    def create_api(self, url: str = None) -> Tuple[str, str]:
        """Create FireProx instance

        :param url: target url to create proxy for
        :returns: (api_id, proxy_url)
        """
        template = self._get_template(url=url)
        response = self.client.import_rest_api(
            parameters={"endpointConfigurationTypes": "REGIONAL"},
            body=template,
        )
        _, proxy_url = self._create_deployment(response["id"])

        return (response["id"], proxy_url)

    def update_api(self, api_id: str, url: str) -> bool:
        """Update FireProx instance

        :param api_id: fireprox instance id
        :param url: target url to create proxy for
        :returns: boolean if api instance was updated
        """
        url = url.rstrip("/")

        # Get resources for the given api
        resource_id = self._get_resource(api_id)
        if resource_id:
            # Update the proxying URL
            response = self.client.update_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="ANY",
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/uri",
                        "value": f"{url}/{{proxy}}",
                    },
                ],
            )

            # Make sure instance updated correctly to new url
            return response["uri"].replace("/{proxy}", "") == url

        else:
            raise FireProxException(f"Unable to update, no valid resource for '{api_id}'")  # fmt: skip

    def delete_api(self, api_id: str) -> bool:
        """Delete FireProx instance

        :param api_id: fireprox instance id
        :returns: boolean if api instance deleted
        """
        items = self.list_api()

        for item in items:
            item_api_id = item["id"]

            if item_api_id == api_id:
                _ = self.client.delete_rest_api(restApiId=api_id)
                return True

        return False

    def list_api(self) -> List[str]:
        """List FireProx instance(s)

        :returns: list of apis
        """
        response = self.client.get_rest_apis()
        return response["items"]


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments and return namespace

    :return: Namespace for arguments
    """
    parser = argparse.ArgumentParser(description="FireProx API Gateway Manager")
    parser.add_argument(
        "--command",
        type=str,
        dest="command",
        choices=["list", "create", "delete", "update"],
        help="Commands: list, create, delete, update",
        required=True,
    )
    parser.add_argument(
        "--profile_name",
        type=str,
        help="AWS Profile Name to store/retrieve credentials",
    )
    parser.add_argument(
        "--access_key",
        type=str,
        help="AWS Access Key",
    )
    parser.add_argument(
        "--secret_access_key",
        type=str,
        help="AWS Secret Access Key",
    )
    parser.add_argument(
        "--session_token",
        type=str,
        help="AWS Session Token",
    )
    parser.add_argument(
        "--region",
        type=str,
        help="AWS Region",
    )
    parser.add_argument(
        "--api_id",
        type=str,
        help="API ID",
    )
    parser.add_argument(
        "--url",
        type=str,
        help="URL end-point",
    )
    args = parser.parse_args()

    return args


def main():
    """Run the main program"""
    args = parse_arguments()

    fp = FireProx(
        url=args.url,
        profile_name=args.profile_name,
        access_key=args.access_key,
        secret_access_key=args.secret_access_key,
        session_token=args.session_token,
        region=args.region,
        command=args.command,
        api_id=args.api_id,
    )

    if args.command == "list":
        result = fp.list_api()
        for r in result:
            print(r)

    elif args.command == "create":
        if not fp.url:
            raise FireProxException("Missing 'url' for 'create'")

        (api_id, proxy_url) = fp.create_api(fp.url)
        print(f"API ID:    {api_id}")
        print(f"Proxy URL: {proxy_url}")

    elif args.command == "delete":
        if not fp.api_id:
            raise FireProxException("Missing 'app_id' for 'delete'")

        result = fp.delete_api(fp.api_id)
        success = "Successfully deleted" if result else "Failed to delete"
        print(f"{success}: '{fp.api_id}'")

    elif args.command == "update":
        if not fp.url:
            raise FireProxException("Missing 'url' for 'update'")
        if not fp.api_id:
            raise FireProxException("Missing 'app_id' for 'update'")

        result = fp.update_api(fp.api_id, fp.url)
        success = "Successfully updated" if result else "Failed to update"
        print(f"{success}: '{fp.api_id}'")


if __name__ == "__main__":
    main()
