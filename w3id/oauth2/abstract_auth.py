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

"""Declare the API for the Authentification policy."""
import abc

class AbstractOAuth2Policy(object):
    """Abstract authentication policy class."""

    @abc.abstractmethod
    async def get(self, request):
        """Abstract function called to get the user_id for the request.

        Args:
            request: aiohttp Request object.

        Returns:
            The user_id for the request, or None if the user_id is not
            authenticated.
        """
        pass

    @abc.abstractmethod
    async def auth_callback(self, request):
        "Process the callback from the OAuth2 engine and redirect to the main page."
        pass
