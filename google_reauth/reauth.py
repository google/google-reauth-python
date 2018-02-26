# Copyright 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A module that provides functions for handling rapt authentication."""

import base64
import getpass
import json
import pyu2f.convenience.authenticator
import pyu2f.errors
import pyu2f.model
import sys

from abc import ABCMeta, abstractmethod
from six import add_metaclass
from six.moves import http_client
from six.moves import urllib
from google_reauth import errors


REAUTH_API = 'https://reauth.googleapis.com/v2/sessions'
REAUTH_SCOPE = 'https://www.googleapis.com/auth/accounts.reauth'
REAUTH_ORIGIN = 'https://accounts.google.com'

REAUTH_NEEDED_ERROR = 'invalid_grant'
REAUTH_NEEDED_ERROR_INVALID_RAPT = 'invalid_rapt'
REAUTH_NEEDED_ERROR_RAPT_REQUIRED = 'rapt_required'


def _handle_errors(msg):
    """Raise an exception if msg has errors.

    Args:
        msg: parsed json from http response.

    Returns: input response.
    Raises: ReauthAPIError
    """
    if 'error' in msg:
        raise errors.ReauthAPIError(msg['error']['message'])
    return msg


def get_user_password(text):
    """Get password from user.

    Override this function with a different logic if you are using this library
    outside a CLI.

    Args:
        text: message for the password prompt.

    Returns: password string.
    """
    return getpass.getpass(text)


def _interactive_check():
    """Check if we are in an interractive environment.

    If the rapt token needs refreshing, the user needs to answer the
    challenges.
    If the user is not in an interractive environment, the challenges can not
    be answered and we just wait for timeout for no reason.

    Returns: True if is interactive environment, False otherwise.
    """

    return sys.stdin.isatty()


def get_print_callback():
    """Get preferred output function.

    Override this function to return a preferred output method, if needed.

    Returns: function to write outout
    """

    return sys.stderr.write


def _send_reauth_challenge_result(http_request, session_id, challenge_id,
                                  client_input, access_token):
    """Attempt to refresh access token by sending next challenge result.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        session_id: session id returned by the initial reauth call.
        challenge_id: challenge id returned by the initial reauth call.
        client_input: dict with a challenge-specific client input. For example:
            {'credential': password} for password challenge
        access_token: reauth access token.

    Returns:
        Parsed http response.
    """
    body = {
        'sessionId': session_id,
        'challengeId': challenge_id,
        'action': 'RESPOND',
        'proposalResponse': client_input,
    }
    _, content = http_request(
        uri='{0}/{1}:continue'.format(REAUTH_API, session_id),
        method='POST',
        body=json.dumps(body),
        headers={'Authorization': 'Bearer ' + access_token}
    )
    response = json.loads(content)
    _handle_errors(response)
    return response


def _get_challenges(http_request, supported_challenge_types, access_token,
                    requested_scopes=None):
    """Does initial request to reauth API to get the challenges.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        supported_challenge_types: list of challenge names supported by the
            manager.
        access_token: reauth access token.
        requested_scopes: scopes required by the user.

    Returns:
        Parsed http response.
    """
    body = {'supportedChallengeTypes': supported_challenge_types}
    if requested_scopes:
        body['oauthScopesForDomainPolicyLookup'] = requested_scopes
    _, content = http_request(
        uri='{0}:start'.format(REAUTH_API),
        method='POST',
        body=json.dumps(body),
        headers={'Authorization': 'Bearer ' + access_token}
    )
    response = json.loads(content)
    _handle_errors(response)
    return response


def _run_refresh_request(http_request, client_id, client_secret, refresh_token,
                         token_uri, scope=None, rapt=None, headers={}):
    """Refresh the access_token using the refresh_token.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        client_id: client id to get access token for reauth scope.
        client_secret: client secret for the client_id
        refresh_token: refresh token to refresh access token
        token_uri: uri to refresh access token
        scopes: scopes required by the client application
        rapt: RAPT token
        headers: headers for http request

    Returns:
        Tuple[str, dict]: http response and parsed response content.
    """
    parameters = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token,
        'scope': scope,
        'rapt': rapt,
    }
    body = urllib.parse.urlencode(parameters)

    return http_request(
        uri=token_uri,
        method='POST',
        body=body,
        headers=headers)


@add_metaclass(ABCMeta)
class ReauthChallenge(object):
    """Base class for reauth challenges."""

    def __init__(self, http_request, access_token):
        self.http_request = http_request
        self.access_token = access_token

    @abstractmethod
    def get_name(self):
        """Returns the name of the challenge."""
        pass

    @abstractmethod
    def is_locally_eligible(self):
        """Returns true if a challenge is supported locally on this machine."""
        pass

    def execute(self, metadata, session_id):
        """Execute challenge logic and pass credentials to reauth API."""
        client_input = self._obtain_credentials(metadata)

        if not client_input:
            return None
        return _send_reauth_challenge_result(
            self.http_request,
            session_id,
            metadata['challengeId'],
            client_input,
            self.access_token)

    @abstractmethod
    def _obtain_credentials(self, metadata):
        """Performs logic required to obtain credentials and returns it."""
        pass


class PasswordChallenge(ReauthChallenge):
    """Challenge that asks for user's password."""

    def get_name(self):
        return 'PASSWORD'

    def is_locally_eligible(self):
        return True

    def _obtain_credentials(self, unused_metadata):
        passwd = get_user_password('Please enter your password:')
        if not passwd:
            passwd = ' '  # avoid the server crashing in case of no password :D
        return {'credential': passwd}


class SecurityKeyChallenge(ReauthChallenge):
    """Challenge that asks for user's security key touch."""

    def get_name(self):
        return 'SECURITY_KEY'

    def is_locally_eligible(self):
        return True

    def _obtain_credentials(self, metadata):
        sk = metadata['securityKey']
        challenges = sk['challenges']
        app_id = sk['applicationId']

        challenge_data = []
        for c in challenges:
            kh = c['keyHandle'].encode('ascii')
            key = pyu2f.model.RegisteredKey(
                bytearray(base64.urlsafe_b64decode(kh)))
            challenge = c['challenge'].encode('ascii')
            challenge = base64.urlsafe_b64decode(challenge)
            challenge_data.append({'key': key, 'challenge': challenge})

        try:
            api = pyu2f.convenience.authenticator.CreateCompositeAuthenticator(
                REAUTH_ORIGIN)
            response = api.Authenticate(app_id, challenge_data,
                                        print_callback=get_print_callback())
            return {'securityKey': response}
        except pyu2f.errors.U2FError as e:
            if e.code == pyu2f.errors.U2FError.DEVICE_INELIGIBLE:
                get_print_callback()('Ineligible security key.\n')
            elif e.code == pyu2f.errors.U2FError.TIMEOUT:
                get_print_callback()(
                    'Timed out while waiting for security key touch.\n')
            else:
                raise e
        except pyu2f.errors.NoDeviceFoundError:
            get_print_callback()('No security key found.\n')
        return None


class ReauthManager(object):
    """Reauth manager class that handles reauth challenges."""

    def __init__(self, http_request, access_token):
        self.http_request = http_request
        self.access_token = access_token
        self.challenges = self._build_challenges()

    def _build_challenges(self):
        out = {}
        for c in [SecurityKeyChallenge(self.http_request, self.access_token),
                  PasswordChallenge(self.http_request, self.access_token)]:
            if c.is_locally_eligible():
                out[c.get_name()] = c
        return out

    def _do_one_round_of_challenges(self, msg):
        next_msg = None
        for challenge in msg['challenges']:
            if challenge['status'] != 'READY':
                # Skip non-activated challneges.
                continue
            c = self.challenges[challenge['challengeType']]
            next_msg = c.execute(challenge, msg['sessionId'])
        return next_msg

    def obtain_proof_of_reauth(self, requested_scopes=None):
        """Obtain proof of reauth (rapt token)."""
        msg = None

        for _ in range(0, 5):

            if not msg:
                msg = _get_challenges(
                    self.http_request,
                    self.challenges.keys(),
                    self.access_token,
                    requested_scopes)

            if msg['status'] == 'AUTHENTICATED':
                return msg['encodedProofOfReauthToken']

            if not (msg['status'] == 'CHALLENGE_REQUIRED' or
                    msg['status'] == 'CHALLENGE_PENDING'):
                raise errors.ReauthAPIError(
                    'Challenge status {0}'.format(msg['status']))

            if not _interactive_check():
                raise errors.ReauthUnattendedError()

            msg = self._do_one_round_of_challenges(msg)

        # If we got here it means we didn't get authenticated.
        raise errors.ReauthFailError()


def _obtain_rapt(http_request, access_token, requested_scopes):
    """Given an http request method and reauth access token, get rapt token.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        access_token: reauth access token
        requested_scopes: scopes required by the client application

    Returns: rapt token.
    Raises:
        errors.ReauthError if reauth failed
    """
    rm = ReauthManager(http_request, access_token)
    rapt = rm.obtain_proof_of_reauth(requested_scopes=requested_scopes)
    return rapt


def get_rapt_token(http_request, client_id, client_secret, refresh_token,
                   token_uri, scopes=None):
    """Given an http request method and refresh_token, get rapt token.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        client_id: client id to get access token for reauth scope.
        client_secret: client secret for the client_id
        refresh_token: refresh token to refresh access token
        token_uri: uri to refresh access token
        scopes: scopes required by the client application

    Returns: rapt token.
    Raises:
        errors.ReauthError if reauth failed
    """
    get_print_callback()('Reauthentication required.\n')

    # Get access token for reauth.
    response, content = _run_refresh_request(
        http_request,
        client_id,
        client_secret,
        refresh_token,
        token_uri,
        REAUTH_SCOPE)

    try:
        content = json.loads(content)
    except (TypeError, ValueError):
        raise errors.ReauthAccessTokenRefreshError(
            'Invalid response {0}'.format(_substr_for_error_message(content)))

    if response.status != http_client.OK:
        raise errors.ReauthAccessTokenRefreshError(
            _get_refresh_error_message(content), response.status)

    if 'access_token' not in content:
        raise errors.ReauthAccessTokenRefreshError(
            'Access token missing from the response')

    # Get rapt token from reauth API.
    rapt_token = _obtain_rapt(
        http_request,
        content['access_token'],
        requested_scopes=scopes)

    return rapt_token


def _rapt_refresh_required(content):
    """Checks if the rapt refresh is required.

    Args:
        content: refresh response content

    Returns:
        True if rapt refresh is required.
    """
    try:
        content = json.loads(content)
    except (TypeError, ValueError):
        return False
    return (
        content.get('error') == REAUTH_NEEDED_ERROR and
        (content.get('error_subtype') == REAUTH_NEEDED_ERROR_INVALID_RAPT or
         content.get('error_subtype') == REAUTH_NEEDED_ERROR_RAPT_REQUIRED))


def _get_refresh_error_message(content):
    """Constructs an error from the http response.

    Args:
        response: http response
        content: parsed response content

    Returns:
        error message to show
    """
    error_msg = 'Invalid response.'
    if 'error' in content:
        error_msg = content['error']
        if 'error_description' in content:
            error_msg += ': ' + content['error_description']
    return error_msg


def _substr_for_error_message(content):
    """Returns content string to include in the error message"""
    return content if len(content) <= 100 else content[0:97] + "..."


def refresh_access_token(http_request, client_id, client_secret, refresh_token,
                         token_uri, rapt=None, scopes=None, headers=None):
    """Refresh the access_token using the refresh_token.

    Args:
        http_request: callable to run http requests. Accepts uri, method, body
            and headers. Returns a tuple: (response, content)
        client_id: client id to get access token for reauth scope.
        client_secret: client secret for the client_id
        refresh_token: refresh token to refresh access token
        token_uri: uri to refresh access token
        scopes: scopes required by the client application

    Returns:
        Tuple[str, str, Optional[str], Optional[str], Optional[str]]: The
            access token, new refresh token, expiration, token id and response
            content returned by the token endpoint.
    Raises:
        errors.ReauthError if reauth failed
        errors.HttpAccessTokenRefreshError it access token refresh failed
    """

    response, content = _run_refresh_request(
        http_request,
        client_id,
        client_secret,
        refresh_token,
        token_uri,
        rapt,
        headers)

    if response.status != http_client.OK:
        # Check if we need a rapt token or if the rapt token is invalid.
        # Once we refresh the rapt token, retry the access token refresh.
        # If we did refresh the rapt token and still got an error, then the
        # refresh token is expired or revoked.

        if (_rapt_refresh_required(content)):
            rapt = get_rapt_token(
                http_request,
                client_id,
                client_secret,
                refresh_token,
                token_uri,
                scopes=scopes,
            )
            # retry with refreshed rapt
            response, content = _run_refresh_request(
                http_request,
                client_id,
                client_secret,
                refresh_token,
                token_uri,
                rapt,
                headers)

    try:
        content = json.loads(content)
    except (TypeError, ValueError):
        raise errors.HttpAccessTokenRefreshError(
            'Invalid response {0}'.format(_substr_for_error_message(content)),
            response.status)

    if response.status != http_client.OK:
        raise errors.HttpAccessTokenRefreshError(
            _get_refresh_error_message(content), response.status)

    access_token = content['access_token']
    refresh_token = content.get('refresh_token', None)
    expires_in = content.get('expires_in', None)
    id_token = content.get('id_token', None)
    return access_token, refresh_token, expires_in, id_token, content
