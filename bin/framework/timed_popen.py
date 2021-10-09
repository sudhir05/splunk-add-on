##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

"""
Popen with timed out in Python 2.7
"""
from subprocess import Popen, PIPE
import time


def _do_read_proc_output(sub):
    stdout = sub.stdout.read()
    stderr = sub.stderr.read()
    sub.wait()
    return [stdout, stderr, False]


class _TerminateCall(object):
    def __init__(self, sub):
        self._sub = sub
        self.timed_out = False

    def __call__(self):
        try:
            self._sub.kill()
        except OSError:
            pass
        else:
            self.timed_out = True
        self._sub = None


def _do_timed_popen(args, timeout):
    """
    This is argly dependence with timer queue service provied by global data
    loader. But I don't want to spawn a separate thread each time when
    timed_popen is called to do a timeout monitor.
    """

    from . import data_loader
    loader = data_loader.GlobalDataLoader.get_data_loader(None, None, None)

    # semgrep ignore reason: not used in TA as of this commit. If used in future make sure it is not controllable by an external resource
    sub = Popen(args, stdout=PIPE, stderr=PIPE) # nosemgrep: python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use
    terminate = _TerminateCall(sub)
    timer = loader.add_timer(terminate, time.time() + timeout, 0)
    ret = _do_read_proc_output(sub)

    if terminate.timed_out:
        ret[-1] = True
    else:
        loader.remove_timer(timer)
    return ret


def timed_popen(args, timeout=-1):
    if timeout > 0:
        return _do_timed_popen(args, timeout)
    else:
        # semgrep ignore reason: not used in TA as of this commit. If used in future make sure it is not controllable by an external resource
        sub = Popen(args, stdout=PIPE, stderr=PIPE) # nosemgrep: python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use
        return _do_read_proc_output(sub)
