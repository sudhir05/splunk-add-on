##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

import time
import socket
import os
import uuid
import json

import snow_ticket as st
import splunk.Intersplunk as si
from snow_consts import FIELD_SEPARATOR

class SnowEventBase(st.SnowTicket):
    """
    Create ServiceNow Event automatically by running as a callback script
    when the corresponding alert is fired
    """

    def _prepare_data(self, event):
        host = event.get("host", socket.gethostname())
        event_data = {"source": "Splunk-{}".format(host)}

        # (field_name, default_value)
        fields = (("node", None), ("resource", None), ("type", None),
                  ("severity", None), ("description", ""),
                  ("time_of_event", ""), ("custom_fields", ""))

        for field, default_val in fields:
            if field == "custom_fields" and event.get(field):
                all_fields = event.get(field).split(FIELD_SEPARATOR)
                for each_field in all_fields:
                    field_kv_list = each_field.split("=", 1)
                    # Verifying that custom fields are in key value format and key is not null
                    if len(field_kv_list) == 2 and field_kv_list[0].strip():
                        event_data.update({field_kv_list[0].strip(): field_kv_list[1].strip()})
                    else:
                        msg = "Custom field '{0}' is not in key value format. Expected format: key1=value||key2=value2 ...".format(str(each_field))
                        self.logger.error(msg)
                        si.parseError(msg)
                        return {'Error Message': msg}
            else:
                val = event.get(field, default_val)
                if val is None:
                    msg = ('Field "{}" is required by ServiceNow '
                        'for creating events'.format(field))
                    self.logger.error(msg)
                    self._handle_error(msg)
                    return None
                event_data[field] = val

        if "ciIdentifier" in event:
            event_data["ci_identifier"] = event["ciIdentifier"]
        elif "ciidentifier" in event:
            event_data["ci_identifier"] = event["ciidentifier"]
        else:
            event_data["ci_identifier"] = event.get("ci_identifier", "")

        additional_info = {
            "url": "",
        }
        if event.get("additional_info"):
            additional_info["url"] = event["additional_info"]
        elif os.environ.get("SPLUNK_ARG_6"):
            additional_info["url"] = os.environ["SPLUNK_ARG_6"]

        event_data["event_class"] = "Splunk"
        correlation_id = uuid.uuid4().hex
        additional_info["correlation_id"] = correlation_id
        event_data["additional_info"] = json.dumps(additional_info)
        if not event_data["time_of_event"]:
            event_data["time_of_event"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                                        time.gmtime())
        return event_data

    def _get_endpoint(self):
        return "api/now/table/em_event"

    def _get_table(self):
        return "em_event"

    def _get_result(self, resp):
        res = {
            "Time of the event": resp["time_of_event"],
            "Source": resp["source"],
            "Node": resp["node"],
            "Type": resp["type"],
            "Resource": resp["resource"],
            "State": resp["state"],
            "Severity": resp["severity"],
            "Sys Id": resp["sys_id"],
            "Event Link": self._get_ticket_link(resp["sys_id"]),
        }

        return res