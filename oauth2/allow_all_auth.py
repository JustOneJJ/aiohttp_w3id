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

"""Implement authentification policy that allows all requests."""
from aiohttp import web

from .abstract_auth import AbstractOAuth2Policy

from .auth import get_oauth2_policy

class AllowAll(AbstractOAuth2Policy):
    "Fake authentification mechanism that allows to pass everything through."

    def __init__(self, use_login):
        self.use_login = use_login

    async def get(self, request):
        "Gets a stock user_id for the request."
        return self.use_login

    async def auth_callback(self, request):
        "No callbacks here. Thank you."
        return web.HTTPForbidden()


def allow_all(request):
    "Returns True if current policy is to allow all logins, False otherwise."
    policy = get_oauth2_policy(request)
    return isinstance(policy, AllowAll)
