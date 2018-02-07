# Copyright 2018 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Implements aiohttp OAuth2 client."""
import abc
from urllib.parse import urlencode, parse_qsl

import json

import aiohttp
from aiohttp import web

# pylint: disable=too-few-public-methods
class Client(object):
    """Base abstract OAuth Client class."""

    shared_key = None
    name = None

    def __init__(self, authorization_endpoint):
        """Initialize the client."""
        self.authorization_endpoint = authorization_endpoint

    def __str__(self):
        """String representation."""
        return "%s %s" % (self.name.title(), self.authorization_endpoint)

    def __repr__(self):
        """String representation."""
        return "<%s>" % self

    @abc.abstractmethod
    def user_parse(self, data):
        """Parse information from provider."""
        pass


class OAuth2Client(Client):
    """Implement OAuth2 client."""

    shared_key = 'code'
    name = 'oauth2'

    encoding = 'utf-8'

    def __init__(self, client_id, client_secret,
                 authorization_endpoint, token_endpoint,
                 **params):
        """Initialize the client."""
        super().__init__(authorization_endpoint)

        self.token_endpoint = token_endpoint

        self.client_id = client_id
        self.client_secret = client_secret
        self.params = params

    def get_authorization_endpoint(self, **params):
        """Return formatted authorize URL."""
        params = dict(self.params, **params)
        params.update({'client_id': self.client_id, 'response_type': self.shared_key})
        return self.authorization_endpoint + '?' + urlencode(params)

    async def request(self, method, url, headers=None, **aio_kwargs):
        """Request OAuth2 resource and return a parsed result."""
        headers = headers or {}

        headers['Accept'] = 'application/json'

        async with aiohttp.ClientSession() as session:
            response = await session.request(method=method, url=url,
                                             headers=headers, **aio_kwargs)

            content_type = response.headers.get('Content-Type')
            if 'html' in content_type:
                # Forward this response to the user
                data = await response.text()
                raise web.HTTPBadRequest(body=data, content_type=content_type)

            if 'json' in content_type:
                data = await response.json()
            else: # some other content type
                data = await response.text()
                data = dict(parse_qsl(data))

            # Handle OAuth2 reported errors
            if 'error' in data:
                raise web.HTTPBadRequest(reason=json.dumps(data))

            return data

    async def _token_endpoint_request(self, form_data, field_name, token):

        # Handle plain request maps here.
        if not isinstance(token, str) and field_name in token:
            token = token[field_name]
        form_data.add_field(field_name, token)

        form_data.add_field('client_id', self.client_id)
        form_data.add_field('client_secret', self.client_secret)

        return await self.request('POST', self.token_endpoint, data=form_data)

    async def get_access_token(self, code):
        """Get an access_token from OAuth2 provider.
        :returns: provider_data
        """
        form_data = aiohttp.FormData(charset=self.encoding)
        form_data.add_field('grant_type', 'authorization_code')

        redirect_uri = self.params.get('redirect_uri')
        if redirect_uri:
            form_data.add_field('redirect_uri', redirect_uri)

        return await self._token_endpoint_request(form_data, self.shared_key, code)

    async def refresh_access_token(self, refresh_token, access_token=None):
        """Get an access_token from OAuth2 provider via `refresh_token`.
        :returns: provider_data
        """
        form_data = aiohttp.FormData(charset=self.encoding)
        form_data.add_field('grant_type', 'refresh_token')
        form_data.add_field('scope', self.params['scope'])

        if not access_token:
            # If access_token is not given, then refresh_token must be a dictionary
            access_token = refresh_token['access_token']

        form_data.add_field('access_token', access_token)

        return await self._token_endpoint_request(form_data, 'refresh_token', refresh_token)

    @abc.abstractmethod
    def user_parse(self, data):
        """Parse information from provider."""
        # This method is here to appease pylint
        pass
