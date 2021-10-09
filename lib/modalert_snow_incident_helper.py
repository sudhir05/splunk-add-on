import os.path as op
import sys
import hashlib

sys.path.insert(0, op.dirname(op.dirname(op.abspath(__file__))))

import snow_incident_base as sib

# encoding = utf-8

class ModSnowIncident(sib.SnowIncidentBase):

    def __init__(self, payload):
        self._payload = payload
        self._config = payload["configuration"]
        self.account = payload["configuration"]["account"]
        self._config["splunk_url"] = payload["configuration"].get("splunk_url") or payload["results_link"]
        # FIXME Should refactor base class
        self._config["ciIdentifier"] = self._config.get("configuration_item", "")
        super(ModSnowIncident, self).__init__()

    def _get_session_key(self):
        return self._payload["session_key"]

    def _get_correlation_id(self, event):
        unique_name = "/".join((self._payload["search_name"],
                                self._payload["owner"],
                                self._payload["app"]))
        # semgrep ignore reason: this is used to generate identifier for snow incident and should not cause security issue but
        # considered as a bug already reported as ADDON-36125
        return hashlib.md5(unique_name.encode()).hexdigest() # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5

    def _get_events(self):
        return self._config,


def process_event(helper, *args, **kwargs):

    # Initialize the class and execute the code for alert action
    helper.log_info("Alert action snow_incident started.")
    handler = ModSnowIncident(helper.settings)
    handler.handle()

    # TODO: Implement your alert action logic here
    return 0
