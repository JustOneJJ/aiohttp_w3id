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

"""Initialize oauth2 module."""
import os
import json

from aiohttp import web

from distutils.util import strtobool

from .decorators import login_required
from .auth import oauth2_middleware, get_oauth2
from .session_auth import SessionOAuth2Authentication
from .allow_all_auth import AllowAll, allow_all
from .w3id_client import W3IDClient


# Expand paths containing shell variable substitutions.
# This expands the forms $variable and ${variable} only.
# Non-existant variables are left unchanged.
_varprog = None

def expandvars(path, environ, start_pos=0):
    """Expand variables of form $var and ${var}.  Unknown variables
       are left unchanged"""
    if start_pos < 0:
        return path
    global _varprog
    if not _varprog:
        import re
        _varprog = re.compile(r'\$(\w+|\{[^}]*\})')
    i = start_pos
    while 1:
        m = _varprog.search(path, i)
        if not m:
            break
        i, j = m.span(0)
        name = m.group(1)
        if name[:1] == '{' and name[-1:] == '}':
            name = name[1:-1]
        expanded = environ.get(name, None)
        if expanded and isinstance(expanded, str):
            tail = path[j:]
            path = path[:i] + expanded
            i = len(path)
            path = path + tail
        else:
            i = j
    return path

def create_policy(config, certificate=None):
    "Create default OAuth2 login policy."
    if strtobool(os.getenv('DISABLE_W3ID_LOGIN_FOR_LOCALHOST', '0')):
        return AllowAll(use_login='localhost')
    else:
        with open(config, 'r') as config_file:
            # Parse config and verify that it is valid
            json_config = json.load(config_file)
            try:
                redirect_uri = json_config.get('redirect_uri', None)
                if redirect_uri:
                    varpos = redirect_uri.find('$')
                    if not varpos < 0:
                        # Optionally expand variables in redirect_url, which is useful
                        # when several projects use the same config file
                        application = json.loads(os.getenv('VCAP_APPLICATION'))
                        json_config['redirect_uri'] = expandvars(redirect_uri, application, start_pos=varpos)
            except:
                pass
            client = W3IDClient(certificate=certificate, **json_config)
            return SessionOAuth2Authentication(client=client)

def setup(app, path, handler):
    "Add OAuth2 callback handler to the `app`."
    app.router.add_get(path, handler.auth_callback)
