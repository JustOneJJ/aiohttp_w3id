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

"""Implement authentification policy via oauth2 and store the result in a session."""
import json

from datetime import datetime
import dateutil.parser

from aiohttp import web
from aiohttp_session import get_session

from .abstract_auth import AbstractOAuth2Policy

class SessionOAuth2Authentication(AbstractOAuth2Policy):
    """Ticket authentication mechanism based on OAuth2, with
    ticket data being stored in a session.
    """

    def __init__(self, client, cookie_name='OAUTH2_OID'):
        self.client = client
        self.cookie_name = cookie_name

    async def _make_cookie(self, request, user_id, data):
        expires_in = int(data['expires_in'])

        # Compute the time when the token expires
        now = datetime.now()

        fields = {
            'user_id'       : user_id,
            'access_token'  : data['access_token'],
            'refresh_token' : data['refresh_token'],
            'creation_time' : now.isoformat(),
            'max_age'       : expires_in
        }

        # store the ticket data for a request. The cookie will be passed onto
        # some response during process_response call
        session = await get_session(request)
        session[self.cookie_name] = json.dumps(fields)

    async def get(self, request):
        """Gets the user_id for the request.

        Gets the ticket for the request using the get_ticket() function, and
        authenticates the ticket.

        Args:
            request: aiohttp Request object.

        Returns:
            The userid for the request, or None if the ticket is not
            authenticated.
        """

        # Load and parse the ticket. If that fails, go to the authorization page.
        user_id = None

        # pylint: disable=bare-except
        try:
            session = await get_session(request)
            ticket = session.get(self.cookie_name)

            fields = json.loads(ticket)

            user_id = fields['user_id']

            # See if the ticket that we have is not getting stale;
            # reissue an update if it is stale.
            creation_time = dateutil.parser.parse(fields['creation_time'])
            max_age = int(fields['max_age'])

            # Compute the time difference in seconds
            tdelta = datetime.now() - creation_time
            if tdelta.total_seconds() > max_age:
                # Get the refresh if possible and update the cookie
                data = await self.client.refresh_access_token(fields)
                await self._make_cookie(request, user_id, data)
        except:
            # Redirect to the login page
            raise web.HTTPFound(self.client.get_authorization_endpoint())

        return user_id

    async def auth_callback(self, request):
        "Process the callback from the OAuth2 engine and redirect to the main page."

        # Report errors if any
        error = request.query.get('error', None)
        if error:
            return web.HTTPBadRequest(reason=error)

        # If we got the code, then query the access token
        code = request.query.get(self.client.shared_key, None)
        if code:
            # Turn a code into an OAuth2 access token
            data = await self.client.get_access_token(code)

            # Verify that we have received the token
            try:
                user_id = self.client.user_parse(data)
                await self._make_cookie(request, user_id, data)
                return web.HTTPFound('/')
            except KeyError:
                raise web.HTTPBadRequest(reason='Failed to obtain OAuth2 access token.')

        # Default response on this page
        return web.HTTPForbidden()
