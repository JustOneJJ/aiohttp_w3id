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

"""Decorators for OAuth2."""
from functools import wraps
from aiohttp import web

from .auth import get_oauth2

def login_required(func):
    """Utility decorator that checks if a user has been authenticated for this
    request.

    Allows views to be decorated like:

        @login_required
        def view_func(request):
            pass

    providing a simple means to ensure that whoever is calling the function has
    the correct authentication details.

    Args:
        func: Function object being decorated and returns HTTPForbidden if not

    Returns:
        A function object that will return web.HTTPForbidden() if the passed
        request does not have the correct permissions to access the view.
    """
    @wraps(func)
    async def _wrapper(*args):
        if (await get_oauth2(args[-1])) is None:
            return web.HTTPForbidden()

        return await func(*args)

    return _wrapper
