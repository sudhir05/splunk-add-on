##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

import uuid
import time
import os
import json
from framework import rest
import snow_ticket as st
import traceback
import snow_oauth_helper as soauth
import re
import splunk.Intersplunk as si

from snow_consts import FIELD_SEPARATOR

class SnowIncidentBase(st.SnowTicket):

    def _prepare_data(self, event):
        event_data = {}
        url = os.environ.get("SPLUNK_ARG_6", "")

        # (field_name, default_value)
        fields = (("category", ""), ("short_description", ""),
                  ("contact_type", ""), ("splunk_url", url), ("urgency", ""),
                  ("subcategory", ""), ("state", "1"), ("comments", ""),
                  ("location", ""), ("impact", "3"),
                  ("correlation_id", ""),
                  ("priority", "4"), ("assignment_group", ""), ("custom_fields", ""))

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
                val = event.get(field)
                if not val:
                    val = default_val
                event_data[field] = val
        
        if "ciIdentifier" in event:
            ci_ident = event["ciIdentifier"]
        elif "ciidentifier" in event:
            ci_ident = event["ciidentifier"]
        else:
            ci_ident = event.get("ci_identifier", "")
        event_data["configuration_item"] = ci_ident
        if not event_data["correlation_id"].strip():
            event_data["correlation_id"] = self._get_correlation_id(event)

        # Limiting correlation_id to 200 characters
        event_data["correlation_id"] = event_data["correlation_id"][0:200]
        self.logger.debug("event_data=%s", event_data)

        return event_data

    def _get_correlation_id(self, event):
        return uuid.uuid4().hex

    def _get_table(self):
        return "x_splu2_splunk_ser_u_splunk_incident"

    def _get_ticket_link(self, sys_id):
        link = "{}incident.do?sysparm_query=correlation_id={}".format(
            self.snow_account["url"], sys_id)

        return link

    def _get_result(self, resp):

        res = {
            "Incident Number": resp.get("number"),
            "Created": resp.get("sys_created_on"),
            "Priority": resp.get("priority"),
            "Updated": resp.get("sys_updated_on"),
            "Short description": resp.get("short_description"),
            "Category": resp.get("category"),
            "Contact Type": resp.get("contact_type"),
            "ciIdentifier": resp.get("configuration_item"),
            "State": resp.get("state"),
            "Sys Id": resp.get("sys_id"),
            "Incident Link": self._get_ticket_link(resp.get("correlation_id")),
            "Correlation ID": resp.get("correlation_id"),
            "Splunk URL": resp.get("splunk_url"),
        }
        return res

    def _handle_response(self, response, content):
        if response.status in (200, 201):
            resp = self._get_resp_record(content)
            if (resp and resp.get("sys_row_error")):
                error_url = resp["sys_row_error"]["link"]

                error_response, error_content = self.execute_http_request(error_url)
                if error_response and error_content:
                    if error_response.status == 200:
                        self.logger.error("Error Message: {0}".format(json.loads(error_content)["result"]["error_message"]))
                        return {"Error Message": json.loads(error_content)["result"]["error_message"]}
                    else:
                        self.logger.error("Failed to get error message of Incident creation failure. Status code: {}, response: {}".format(
                            error_response.status, error_content
                        ))
                        return {"Error Message": "Failed to get error message of Incident creation failure. Status code: {}, response: {}".format(
                            error_response.status, error_content
                        )}

        return super(SnowIncidentBase, self)._handle_response(response, content)

    def execute_http_request(self, rest_uri, method="GET", data=None, msg=""):
        '''
        This is a helper function will execute the rest api call to the ServiceNow instance based on the authentication type selected by the user
        '''

        headers = {
            "Content-type": "application/json",
            "Accept":"application/json"
        }
        response = None
        content = None

        http = rest.build_http_connection(self.snow_account)

        if self.snow_account["auth_type"] == "oauth":
            headers.update({
                "Authorization": "Bearer %s" % self.snow_account["access_token"]
            })

        # Executing the rest api call
        try:
            for retry in range(3):
                # Reloading the headers with the regenerated oauth access token
                if retry > 0 and self.snow_account["auth_type"] == "oauth":
                    self.logger.info("Retry count: {}/3".format(retry + 1))
                    headers.update({
                        "Authorization": "Bearer %s" % self.snow_account["access_token"]
                    })
                self.logger.info("Initiating request to {}".format(rest_uri))
                response, content = http.request(
                    rest_uri,
                    method=method,
                    headers=headers,
                    body=data
                )

                if response.status not in (200, 201):
                    # If HTTP status = 401, there is a possibility that access token is expired if auth_type = oauth
                    if response.status == 401 and self.snow_account["auth_type"] == "oauth":
                        self.logger.error("Failure occurred while connecting to {0}. The reason for failure={1}. Failure "
                                          "potentially caused by expired access token. Regenerating access token.".format(
                                          rest_uri, response.reason))
                        snow_oauth = soauth.SnowOAuth(self.snow_account, "ticket")
                        update_status = snow_oauth.regenerate_oauth_access_tokens()

                        if update_status:
                            # Reloading the self.snow_account dictionary with the new tokens generated
                            self.snow_account = self._get_service_now_account()
                            continue
                        else:
                            self.logger.error("Unable to generate new access token. Failure potentially caused by "
                                            "the expired refresh token. To fix the issue, reconfigure the account and try again.")
                            break

                    # Error is not related to access token expiration. Hence breaking the loop
                    else:
                        break
                # Response obtained successfully. Hence breaking the loop
                else:
                    break

        except Exception:
            if msg:
                self.logger.error(msg)
            self.logger.error(traceback.format_exc())


        return response, content

    def _get_incident_failure_message(self):
        return None
