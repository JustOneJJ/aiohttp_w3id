# w3id

Authentication middleware plugin for aiohttp.

This library provides an authentication middleware plugin for aiohttp servers. The oauth2_middleware plugin is a simple
system for authenticating a user, and ensuring that an unauthenticated user cannot access those resources that require
authentication.

# oauth2_middleware Usage

The oauth2_middleware plugin provides a simple abstraction for remembering and retrieving the authentication details for
a user across http requests. Typically, an application would retrieve the login details for a user, and call the remember
function to store the details. These details can then be recalled in future requests.


```Python
from w3id import oauth2
from aiohttp import web

@oauth2.login_required
async def my_index_view(request):
    user_id = await oauth2.get_oauth2(request)

    return web.json_response({'Hi': user_id})
```

The actual mechanisms for storing the authentication credentials are passed as a policy to the session manager middleware.
New policies can be implemented quite simply by overriding the AbstractOAuth2Policy class. This package currently provides
a policy that uses the aiohttp_session class to store authentication tickets -- SessionOAuth2Authentication.

# Initialization

```Python
from aiohttp_session import session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage

def init(loop):

    # Create a default w3id authentification policy
    policy = oauth2.create_policy(config='config/w3id.json',
                                  certificate='config/oidc_w3id.cer') # Optional

    middlewares = [
        session_middleware(EncryptedCookieStorage(os.urandom(32), secure=True)),
        oauth2.oauth2_middleware(policy)
    ]

    app = web.Application(loop=loop, middlewares=middlewares)
```

# Licensing

Copyright 2018 IBM Corp.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
