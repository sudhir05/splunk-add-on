##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

import os
import sys

sys.path.insert(0, os.path.sep.join([os.path.dirname(os.path.realpath(os.path.dirname(__file__))), 'lib']))

import http
import queue

assert 'Splunk_TA_snow' not in http.__file__
assert 'Splunk_TA_snow' not in queue.__file__
