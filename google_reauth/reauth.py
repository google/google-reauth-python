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
from six.moves import urllib
from google_reauth import errors


REAUTH_API = 'https://reauth.googleapis.com/v2/sessions'
REAUTH_SCOPE = 'https://www.googleapis.com/auth/accounts.reauth'
REAUTH_ORIGIN = 'https://accounts.google.com'


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


class ReauthChallenge(object):
    """Base class for reauth challenges."""

    __metaclass__ = ABCMeta

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

        body = {
            'sessionId': session_id,
            'challengeId': metadata['challengeId'],
            'action': 'RESPOND',
            'proposalResponse': client_input,
        }
        _, content = self.http_request(
            '{0}/{1}:continue'.format(REAUTH_API, session_id),
            method='POST',
            body=json.dumps(body),
            headers={'Authorization': 'Bearer ' + self.access_token}
        )
        response = json.loads(content)
        _handle_errors(response)
        return response

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

    def _start(self, requested_scopes):
        """Does initial request to reauth API and initialize the challenges."""
        body = {'supportedChallengeTypes': self.challenges.keys()}
        if requested_scopes:
            body['oauthScopesForDomainPolicyLookup'] = requested_scopes
        _, content = self.http_request(
            '{0}:start'.format(REAUTH_API),
            method='POST',
            body=json.dumps(body),
            headers={'Authorization': 'Bearer ' + self.access_token}
        )
        response = json.loads(content)
        _handle_errors(response)
        return response

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
                msg = self._start(requested_scopes)

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
        http_request: function to run http requests
        access_token: reauth access token
        requested_scopes: scopes required by the client application

    Returns: rapt token.
    Raises:
        ReauthAccessTokenRefreshError if a request for an access token failed.
        ReauthUnattendedError if it's not aninteractive environment
        ReauthAPIError if a request to the reauth API failed
        ReauthFailError if we couldn't get a rapt token after 5 round of
            challanges
    """
    rm = ReauthManager(http_request, access_token)
    rapt = rm.obtain_proof_of_reauth(requested_scopes=requested_scopes)
    return rapt


def get_rapt_token(http_request, client_id, client_secret, refresh_token,
                   token_uri, scopes=None):
    """Given an http request method and refresh_token, get rapt token.

    Args:
        http_request: function to run http requests
        client_id: client id to get access token for reauth scope.
        client_secret: client secret for the client_id
        refresh_token: refresh token to refresh access token
        token_uri: uri to refresh access token
        scopes: scopes required by the client application

    Returns: rapt token.
    Raises:
        ReauthAccessTokenRefreshError if a request for an access token failed.
        ReauthUnattendedError if it's not aninteractive environment
        ReauthAPIError if a request to the reauth API failed
        ReauthFailError if we couldn't get a rapt token after 5 round of
            challanges
    """
    get_print_callback()('Reauthentication required.\n')

    # Get access token for reauth.
    query_params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token,
        'scope': REAUTH_SCOPE,
        'grant_type': 'refresh_token',
    }
    _, content = http_request(
        token_uri,
        method='POST',
        body=urllib.parse.urlencode(query_params),
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try:
        reauth_access_token = json.loads(content)['access_token']
    except (ValueError, KeyError):
        raise errors.ReauthAccessTokenRefreshError

    # Get rapt token from reauth API.
    rapt_token = _obtain_rapt(
        http_request,
        reauth_access_token,
        requested_scopes=scopes)

    return rapt_token
