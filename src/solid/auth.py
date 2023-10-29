import httpx
from httpx import Response

from solid_oidc_client import SolidOidcClient, SolidAuthSession, MemStore
import flask
import threading

from typing import Dict

class Auth:
    def __init__(self):
        self.client = httpx.Client()

    @property
    def is_login(self) -> bool:
        return self.client.cookies.get('nssidp.sid') is not None

    def login(self, idp, username, password):
        # NSS only
        if idp[-1] == '/':
            idp = idp[:-1]
        url = '/'.join((idp, 'login/password'))

        data = {
            'username': username,
            'password': password
        }

        r = self.client.post(url, data=data)
        r.raise_for_status()

        if not self.is_login:
            raise Exception('Cannot login.')


class OidcAuth:

    OAUTH_CALLBACK_PATH = '/oauth/callback'
    OAUTH_CALLBACK_URI = f"http://localhost:8080{OAUTH_CALLBACK_PATH}"

    def __init__(self):
        self.client = httpx.Client()
        self.session = None
        self._server_finished = threading.Condition()
        self._solid_oidc_client = None

    @property
    def is_login(self) -> bool:
        return self.session is not None

    def fetch(self, method, url, options: Dict) -> Response:
        if 'headers' not in options:
            options['headers'] = {}

        if self.session:
            auth_headers = self.session.get_auth_headers(url, method)
            options['headers'].update(auth_headers)

        r = self.client.request(method, url, **options)
        return r

    def _start_server(self):

        app = flask.Flask(__name__)

        @app.get('/oauth/callback')
        def login_callback():
            code = flask.request.args['code']
            state = flask.request.args['state']

            session = self._solid_oidc_client.finish_login(
                code=code,
                state=state,
                callback_uri=OidcAuth.OAUTH_CALLBACK_URI,
            )
            self.session = session

            with self._server_finished:
                self._server_finished.notify_all()

            return flask.Response(
                                f"Logged in as {self.session.get_web_id()}. You can close your browser now.",
                                mimetype='text/html')

        @app.post('/stop')
        def stop_server():
            func = flask.request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()

        thread = threading.Thread(target=app.run, args=('localhost', 8080))
        thread.start()

    def _stop_server(self):
        self.client.post('http://localhost:8080/stop')
        self._solid_oidc_client = None

    def login(self, idp):
        self._solid_oidc_client = SolidOidcClient(storage=MemStore())
        self._start_server()

        self._solid_oidc_client.register_client(idp, [OidcAuth.OAUTH_CALLBACK_URI])
        login_url = self._solid_oidc_client.create_login_uri('/', OidcAuth.OAUTH_CALLBACK_URI)
        print(f"Please visit this URL to log-in: {login_url}")

        with self._server_finished:
            self._server_finished.wait_for(lambda: self.session)

        self._stop_server()
