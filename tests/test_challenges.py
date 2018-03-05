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

from google_reauth import challenges

import pyu2f


class ChallangesTest(unittest.TestCase):
    """This class contains tests for reauth challanges. """

    # This U2F mock is made by looking into the implementation of the class and
    # making the minimum requirement to actually answer a challenge.
    class _U2FInterfaceMock(object):
        def Authenticate(self, unused_app_id, challenge, unused_registered_keys):
            raise self.error

    def StartPatch(self, *args, **kwargs):
        patcher = mock.patch(*args, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    #######
    # Helper functions and classes above.
    # Actual tests below.
    #######

    def testSecurityKeyError(self):
        metadata = {
            'status': 'READY',
            'challengeId': 2,
            'challengeType': 'SECURITY_KEY',
            'securityKey': {
                'applicationId': 'security_key_application_id',
                'challenges': [{
                    'keyHandle': 'some_key',
                    'challenge': base64.urlsafe_b64encode('some_challenge'),
                }]
            }}

        u2f_interface_mock = self._U2FInterfaceMock()
        self.u2f_local_interface_mock = self.StartPatch(
            'pyu2f.u2f.GetLocalU2FInterface')
        self.u2f_local_interface_mock.return_value = u2f_interface_mock

        challenge = challenges.SecurityKeyChallenge()

        u2f_interface_mock.error = pyu2f.errors.U2FError(
            pyu2f.errors.U2FError.DEVICE_INELIGIBLE)
        self.assertEquals(None, challenge.obtain_credentials(metadata))

        u2f_interface_mock.error = pyu2f.errors.U2FError(
            pyu2f.errors.U2FError.TIMEOUT)
        self.assertEquals(None, challenge.obtain_credentials(metadata))

        u2f_interface_mock.error = pyu2f.errors.NoDeviceFoundError()
        self.assertEquals(None, challenge.obtain_credentials(metadata))

        u2f_interface_mock.error = pyu2f.errors.U2FError(
            pyu2f.errors.U2FError.BAD_REQUEST)
        with self.assertRaises(pyu2f.errors.U2FError):
            challenge.obtain_credentials(metadata)

        u2f_interface_mock.error = pyu2f.errors.UnsupportedVersionException()
        with self.assertRaises(pyu2f.errors.UnsupportedVersionException):
            challenge.obtain_credentials(metadata)

    def testNoPassword(self):
        getpass_mock = self.StartPatch('getpass.getpass')
        getpass_mock.return_value = None
        self.assertEquals(challenges.PasswordChallenge().obtain_credentials({}),
            {'credential': ' '})

    def testBuildChallenges(self):
        self.assertEquals(sorted(challenges.build_challenges().keys()), [
            'PASSWORD', 'SECURITY_KEY'])

        challenge_mock = self.StartPatch(
            'google_reauth.challenges.SecurityKeyChallenge.is_locally_eligible')
        challenge_mock.return_value = False
        self.assertEquals(sorted(challenges.build_challenges().keys()), [
            'PASSWORD'])
