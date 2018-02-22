# Copyright 2015 Google Inc. All rights reserved.
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

"""Tests for the reauth module."""

import base64
import json
import os
import unittest

import mock

from six.moves import urllib

from oauth2client import client

try:
    from google_reauth import reauth
    from google_reauth import reauth_errors
    from google_reauth import reauth_creds
    from google_reauth.reauth_creds import Oauth2WithReauthCredentials
except ImportError:
    reauth = None

try:
    from pyu2f import model
    from pyu2f import u2f
except ImportError:
    model = None
    u2f = None


class ReauthTest(unittest.TestCase):
    """This class contains tests for mocking reauth.

    The tests here are a bit more verbose since we are trying to mock out U2F, and
    present the reauth code some form of valid reply. This makes this test a bit
    of an integration test, as opposed to testing every individual method by
    itself.
    """

    rapt_token = 'encoded_proof_of_reauth_token'
    correct_password = 'correct_password'
    oauth_api_url = 'http://some_url.com'
    client_id = 'some_id'
    client_secret = 'some_secret'

    def _request_mock_side_effect(self, *args, **kwargs):
        """Helper function to respond with valid requests as if a real server.

        This is the helper function for mocking HTTP calls. The calls that should
        end up here are to the oauth2 API or to the reauth API. The order of ifs
        tries to mimic the real order that the requests are expected, but we do not
        enforce a particular order so it can be more general.

        Args:
          *args: Every arg passed to a request.
          **kwargs: Every keyed arg passed to a request.

        Returns:
          (str, str), Mocked (headers, content)

        Raises:
          Exception: In case this function doesn't know how to mock a request.
        """

        # Requests to oauth2 have the body urlencoded.
        # Requests to reauth have a JSON body.
        # Try to decode both and use as needed.
        qp = dict(urllib.parse.parse_qsl(kwargs['body']))
        try:
            qp_json = json.loads(kwargs['body'])
        except ValueError:
            qp_json = {}

        # First call to oauth2 has REAUTH_SCOPE and returns an access token.
        if ((args[0] == self.oauth_api_url and
             qp.get('scope') == reauth.REAUTH_SCOPE)):
            return None, json.dumps({'access_token': 'access_token_for_reauth'})

        # Initialization call for reauth, serve first challenge
        if args[0] == (reauth.REAUTH_API + ':start'):
            return None, json.dumps({
                'status': 'CHALLENGE_REQUIRED',
                'sessionId': 'session_id_1',
                'challenges': [{
                    'status': 'READY',
                    'challengeId': 1,
                    'challengeType': 'PASSWORD',
                    'securityKey': {},
                }],
            })

        # Continuation call for reauth, check first challenge and serve the second
        if args[0] == (reauth.REAUTH_API + '/session_id_1:continue'):
            self.assertEqual(1, qp_json.get('challengeId'))
            self.assertEqual('RESPOND', qp_json.get('action'))

            if (qp_json.get('proposalResponse', {}).get('credential')
                == self.correct_password):
                # We got a correct password, go to security key
                return None, json.dumps({
                    'status': 'CHALLENGE_REQUIRED',
                    'sessionId': 'session_id_2',
                    'challenges': [{
                        'status': 'READY',
                        'challengeId': 2,
                        'challengeType': 'SECURITY_KEY',
                        'securityKey': {
                            'applicationId': 'security_key_application_id',
                            'challenges': [{
                                'keyHandle': 'some_key',
                                'challenge': base64.urlsafe_b64encode('some_challenge'),
                            }],
                        },
                    }],
                })
            else:
                # We got an incorrect password, ask again.
                # Normally, the sessionID should be different, but for keeping this
                # function simple, we are going to reuse session_id_1 to come back to
                # this if block.
                return None, json.dumps({
                    'status': 'CHALLENGE_PENDING',
                    'sessionId': 'session_id_1',
                    'challenges': [{
                        'status': 'READY',
                        'challengeId': 1,
                        'challengeType': 'PASSWORD',
                        'securityKey': {},
                    }],
                })

        # Continuation call for reauth, check second challenge and serve token
        if args[0] == (reauth.REAUTH_API + '/session_id_2:continue'):
            self.assertEqual(2, qp_json.get('challengeId'))
            self.assertEqual('RESPOND', qp_json.get('action'))
            return None, json.dumps({
                'status': 'AUTHENTICATED',
                'sessionId': 'session_id_3',
                'encodedProofOfReauthToken': self.rapt_token,
            })

        raise Exception(
            'Unexpected call :/\nURL {0}\n{1}'.format(args[0], kwargs['body']))

  # This U2F mock is made by looking into the implementation of the class and
  # making the minimum requirement to actually answer a challenge.
    class _U2FInterfaceMock(object):

        def Authenticate(self, unused_app_id, challenge, unused_registered_keys):
            client_data = model.ClientData(
                model.ClientData.TYP_AUTHENTICATION,
                challenge,
                'some_origin')
            return model.SignResponse('key_handle', 'resp', client_data)

    def _call_reauth(self):
        if os.environ.get('SK_SIGNING_PLUGIN') is not None:
            raise unittest.SkipTest('unset SK_SIGNING_PLUGIN.')
        return reauth.GetRaptToken(
            self.request_mock,
            self.client_id,
            self.client_secret,
            'some_refresh_token',
            self.oauth_api_url,
            scopes=None)

    def StartPatch(self, *args, **kwargs):
        patcher = mock.patch(*args, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

  #######
  # Helper functions and classes above.
  # Actual tests below.
  #######

    def setUp(self):
        if u2f:
            self.u2f_local_interface_mock = self.StartPatch(
                'pyu2f.u2f.GetLocalU2FInterface')
            self.u2f_local_interface_mock.return_value = self._U2FInterfaceMock()

        self.request_mock = self.StartPatch('httplib2.Http.request')
        self.request_mock.side_effect = self._request_mock_side_effect

        self.getpass_mock = self.StartPatch('getpass.getpass')
        self.getpass_mock.return_value = self.correct_password

        self.is_interactive_mock = self.StartPatch('sys.stdin')
        self.is_interactive_mock.isatty = lambda: True

    def testPassAndGnubbyReauth(self):
        if not u2f or not reauth:
            raise unittest.SkipTest('Needs pyu2f library.')
        reauth_result = self._call_reauth()
        self.assertEqual(self.rapt_token, reauth_result)
        self.assertEqual(4, self.request_mock.call_count)

    def testIncorrectPassThenPassAndGnubbyReauth(self):
        if not u2f or not reauth:
            raise unittest.SkipTest('Needs pyu2f library.')
        self.getpass_mock.return_value = None
        self.getpass_mock.side_effect = ['bad_pass', self.correct_password]
        reauth_result = self._call_reauth()
        self.assertEqual(self.rapt_token, reauth_result)
        self.assertEqual(5, self.request_mock.call_count)

    def testNonInteractiveError(self):
        if not u2f or not reauth:
            raise unittest.SkipTest('Needs pyu2f library.')
        self.is_interactive_mock.isatty = lambda: False
        with self.assertRaises(reauth_errors.ReauthUnattendedError):
            unused_reauth_result = self._call_reauth()

    def testFromOAuth2Credentials(self):
        if not u2f or not reauth:
            raise unittest.SkipTest('Needs pyu2f library.')
        orig = client.OAuth2Credentials(
            access_token='at', client_id='ci', client_secret='cs',
            refresh_token='rt', token_expiry='te', token_uri='tu',
            user_agent='ua')
        cred = Oauth2WithReauthCredentials.from_OAuth2Credentials(orig)
        self.assertEqual('Oauth2WithReauthCredentials', cred.__class__.__name__)
        self.assertEqual('ci', cred.client_id)
        self.assertEqual('cs', cred.client_secret)
