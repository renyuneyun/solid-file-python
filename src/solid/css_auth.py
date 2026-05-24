try:
    from solid_oidc_client import SolidAuthSession
    from solid_oidc_client.dpop_utils import create_dpop_token
    from jwcrypto import jwk
except ImportError as e:
    raise ImportError(
        "CSS authentication requires optional dependencies. "
        "Install them with: pip install solid-file[css]"
    ) from e

import httpx
from httpx import Response
from typing import Dict


class CssAuth:
    """Auth for Community Solid Server using OAuth2 client credentials + DPoP.

    The client credentials should be created, e.g. via the CSS web UI
      (Account > Settings > Tokens).
    They are **NOT** your CSS username and password.
    """

    def __init__(self):
        self.client = httpx.Client()
        self.session = None

    @property
    def is_login(self) -> bool:
        return self.session is not None

    def login(self, idp, client_id, client_secret):
        if idp.endswith('/'):
            idp = idp[:-1]

        key = jwk.JWK.generate(kty='EC', crv='P-256')

        r = self.client.get(f"{idp}/.well-known/openid-configuration")
        r.raise_for_status()
        token_endpoint = r.json()['token_endpoint']

        dpop_proof = create_dpop_token(key, token_endpoint, 'POST')
        r = self.client.post(
            token_endpoint,
            data={"grant_type": "client_credentials", "scope": "webid"},
            headers={"DPoP": dpop_proof},
            auth=(client_id, client_secret),
        )
        r.raise_for_status()
        access_token = r.json()['access_token']

        self.session = SolidAuthSession(access_token, key)

    def fetch(self, method, url, options: Dict) -> Response:
        if 'headers' not in options:
            options['headers'] = {}
        if self.session:
            options['headers'].update(self.session.get_auth_headers(url, method))
        return self.client.request(method, url, **options)
