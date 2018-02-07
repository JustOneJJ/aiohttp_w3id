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

"""Implement OAuth2 authorization."""
from .abstract_auth import AbstractOAuth2Policy

# Key used to store the auth policy in the request object
OAUTH2_POLICY_KEY = 'w3id_oauth2.policy'

# Key used to cache the auth credentials in the request object
OAUTH2_AUTH_KEY = 'w3id_oauth2.auth'


def oauth2_middleware(policy):
    """Returns a oauth2_middleware middleware factory for use by the aiohttp
    application object.

    Args:
        policy: A authentication policy with a base class of
            AbstractOAuth2Policy.
    """
    assert isinstance(policy, AbstractOAuth2Policy)

    async def _auth_middleware_factory(app, handler):

        # pylint: disable=unused-argument
        async def _middleware_handler(request):
            # Save the policy in the request
            request[OAUTH2_POLICY_KEY] = policy

            # Call the next handler in the chain
            return await handler(request)

        return _middleware_handler

    return _auth_middleware_factory


def get_oauth2_policy(request):
    """Returns the policy associated with a particular `request`.

    Args:
        request: aiohttp Request object.

    Raises:
        RuntimeError: Middleware is not installed
    """
    policy = request.get(OAUTH2_POLICY_KEY)
    if policy is None:
        raise RuntimeError('oauth2_middleware is not installed')
    return policy


async def get_oauth2(request):
    """Returns the user_id associated with a particular `request`.

    Args:
        request: aiohttp Request object.

    Returns:
        The user_id associated with the request, or None if no user is
        associated with the request.

    Raises:
        RuntimeError: Middleware is not installed
    """

    auth_val = request.get(OAUTH2_AUTH_KEY)
    if auth_val:
        return auth_val

    auth_policy = get_oauth2_policy(request)

    # Cache policy invocations
    request[OAUTH2_AUTH_KEY] = await auth_policy.get(request)
    return request[OAUTH2_AUTH_KEY]
