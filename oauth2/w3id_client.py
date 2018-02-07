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

"""Implement a certificate verifying secure IBM w3id client."""
import jwt

from jwt.exceptions import InvalidTokenError, InvalidKeyError

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

from aiohttp import web

from .client import OAuth2Client

class W3IDClient(OAuth2Client):
    "Implement w3id OAuth2 client for IBM w3id service."

    def __init__(self, certificate, **params):
        super().__init__(**params)

        self.public_key = ''
        if certificate:
            with open(certificate, 'rb') as cert_file:
                cert_obj = load_pem_x509_certificate(cert_file.read(), default_backend())
                self.public_key = cert_obj.public_key()

    def user_parse(self, data):
        """Parse information from provider."""
        id_token = data['id_token']

        try:
            # Verify payload only if public key is known
            payload = jwt.decode(id_token, self.public_key,
                                 audience=self.client_id,
                                 verify=bool(self.public_key),
                                 algorithms=['RS256'])

            return payload['emailAddress']
        except (InvalidTokenError, InvalidKeyError) as einfo:
            raise web.HTTPNetworkAuthenticationRequired(reason=str(einfo))
