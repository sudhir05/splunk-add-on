##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

import sys
import base64
import json
import os.path as op
import threading
import traceback
from datetime import datetime
from datetime import timedelta
import re

import framework.log as log
import snow_consts as sc
import snow_oauth_helper as soauth
from framework import rest
from framework import utils

_LOGGER = log.Logs().get_logger("main")


class _ObjectWrapper(object):

    def __init__(self, obj, table, endpoint, timefield, input_name):
        self.obj = obj
        self.table = table
        self.endpoint = endpoint
        self.timefield = timefield
        self.input_name = input_name

    def to_string(self, idx, host, excludes=()):
        evt_fmt = ("<event stanza=\"snow://{0}\"><time>{1}</time><source>{2}</source>"
                   "<sourcetype>{3}</sourcetype><host>{4}</host>"
                   "<index>{5}</index><data>endpoint=\"{6}\",{7}</data>"
                   "</event>")
        tag_vals = ",".join(("{0}=\"{1}\"".format(
            k, str(v).replace('"', ""))
            for k, v in self.obj.items()
            if k not in excludes))

        try:
            timestamp = datetime.strptime(self.obj[self.timefield],
                                          "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = datetime.utcnow()
        return evt_fmt.format(self.input_name, utils.datetime_to_seconds(timestamp),
                              self.endpoint, "snow:" + self.table, host, idx,
                              self.endpoint, utils.escape_cdata(tag_vals))


class Snow(object):
    _SUPPORTED_DISPLAY_VALUES = ["false", "true", "all"]

    def __init__(self, config):
        """
        @config: dict like, should have url, username, checkpoint_dir,
                 since_when, proxy_url, proxy_username, proxy_password
        """

        host = config["url"]
        self.auth_type = config["auth_type"]

        if isinstance(host, str):
            prefix = re.search("^https?://", host)
            if not prefix:
                host = "https://{0}".format(host)

            if not host.endswith("/"):
                host = "{0}/".format(host)
        else:
            _LOGGER.critical("Please check your splunk_ta_snow_account.conf, the 'url' "
                             "value is missing. Please add valid 'url' in "
                             "splunk_ta_snow_account.conf and restart your instance. Exiting TA.")
            sys.exit(1)
        if self.auth_type == "basic" and (not config["username"] or not config["password"]):
            _LOGGER.critical("Please check your splunk_ta_snow_account.conf, the 'username' and/or "
                             "'password' value are missing. Please recreate the input as this "
                             "input is malformed. Exiting TA.")
            sys.exit(1)

        elif self.auth_type == "oauth" and (not config["access_token"] or not config["refresh_token"] or not config["client_id"] or not config["client_secret"]):
            _LOGGER.critical("Please check your splunk_ta_snow_account.conf, one or more of the required parameters: 'client_id',"
                             " 'client_secret', 'access_token', 'refresh_token' are missing. Please recreate the input as this "
                             "input is malformed. Exiting TA.")
            sys.exit(1)

        self.host = host
        self.account = config["account"]

        # For auth_type="basic", username and password will be required for data collection
        if self.auth_type == "basic":
            self.username = config["username"]
            self.password = config["password"]
        # For auth_type="outh", access_token and refresh_token will be required for data collection
        else:
            self.oauth_access_token = config["access_token"]
            self.oauth_refresh_token = config["refresh_token"]

        self.checkpoint_dir = config["checkpoint_dir"]
        if config["since_when"] == "now":
            now = datetime.utcnow() - timedelta(7)
            self.since_when = datetime.strftime(now, "%Y-%m-%d %H:%M:%S")
        else:
            self.since_when = config["since_when"]
        self.id_field = config.get("id_field") or "sys_id"
        self.filter_data = config.get("filter_data", "")
        self.include_list = (config.get("include") or "").replace(" ", "")
        self.config = config
        self.context = {}
        self._lock = threading.Lock()
        self._display_value = self._get_display_value(config)

    def _get_display_value(self, config):
        dv = config.get("display_value", "")
        if utils.is_false(dv):
            return "false"
        if utils.is_true(dv):
            return "true"
        if dv and dv in self._SUPPORTED_DISPLAY_VALUES:
            return dv
        return sc.DEFAULT_DISPLAY_VALUE

    @staticmethod
    def _rebuild_json_node(json_obj):
        # For latest api, field is returned as dict which contains
        # value and display_value.
        node = {}
        for k, v in json_obj.items():
            if not isinstance(v, dict):
                node[k] = v
            else:
                node[k] = v.get("value", "")
                node["dv_%s" % k] = v.get("display_value", "")
        return node

    def _flat_json_records(self, records):
        _LOGGER.debug("Start to rebuild json content.")
        if self._display_value != "all":
            # For old api, field and display value which starts with 'dv_'
            # are returned together. We don't need to do anything.
            return records
        results = []
        for item in records:
            results.append(self._rebuild_json_node(item))
        _LOGGER.debug("Rebuild json content end.")
        return results

    def collect_data(self, table, timefield, input_name, host, excludes, count=sc.DEFAULT_RECORD_LIMIT):
        assert table and timefield
        if not count:
            count = sc.DEFAULT_RECORD_LIMIT

        #setting the upper limit for the time range (FROM - TO) to collect data.
        now = (datetime.strftime(datetime.utcnow(), "%Y-%m-%d+%H:%M:%S"))
        checkpoint_file_name = ".".join((input_name, timefield))
        
        while True:
            _write_checkpoint_status = 0
            with self._lock:
                last_timestamp, next_offset = self._read_last_collection_time_and_offset(input_name, timefield)
                #setting the query for time range and ordering of events in the serviccnow table
                #e.g. sys_updated_on>=2000-01-01+06:44:36^sys_updated_on<2020-12-08+06:51:45^ORDERBYsys_updated_on,sys_id
                params = "{0}>={1}^{0}<{3}^ORDERBY{0},{2}".format(timefield, last_timestamp, self.id_field, now)
                _, content = self._do_collect(table, params, next_offset, limit=count)
                if not content:
                    return
                try:
                    jobjs = self._json_to_objects(content)
                except Exception as e:
                    _LOGGER.error("Failure occurred while getting records for the table: {1} from {0}. The reason for failure= {2}. Contact Splunk administrator "
                                "for further information.".format(self.host, table, str(e)))
                    return
                records = jobjs.get("result")

                if jobjs.get("error"):
                    _LOGGER.error("Failure occurred while getting records for the table: {1} from {0}. The reason for failure= {2}. Contact Splunk administrator "
                                "for further information.".format(self.host, table, str(jobjs["error"])))
                    return
                
                if not records:
                    # no records are returned by the API call.
                    self.context[checkpoint_file_name]["last_collection_time"] = now.replace("+"," ")
                    self.context[checkpoint_file_name]["next_offset"] = 0
                    _write_checkpoint_status = self._write_checkpoint(input_name, timefield, records)
                    if not _write_checkpoint_status:
                        return None
                    _LOGGER.info(
                        "Data collection completed for input {0}. Got a total of {1} records from {2}{3}.".format(
                            input_name, next_offset, self.host, table))
                    return

                jobjs = self._flat_json_records(records)
                self._write_events_to_event_queue(jobjs, table, timefield, input_name, host, excludes)
                self.context[checkpoint_file_name]["next_offset"] = next_offset + len(jobjs)

                if self.context[checkpoint_file_name].get("last_time_records") and jobjs:
                    # setting offset using older version of checkpoint if any exist.
                    # this is used to minimize data duplication during upgrade.
                    self.context[checkpoint_file_name]["last_time_records"], jobjs = self._remove_collected_records(
                        self.context[checkpoint_file_name]["last_time_records"], jobjs)

                _write_checkpoint_status = self._write_checkpoint(input_name, timefield, jobjs)

            if not _write_checkpoint_status:
                return None

            _LOGGER.info("Data collection is in progress for input {0}. Got {1} records for the table: {3} from {2}."
                        .format(input_name, len(jobjs), self.host, table))

    def _write_events_to_event_queue(self, jobjs, table, timefield, input_name, host, excludes):
        """
        This method writes events to the event queue after pre-processing.
        :param jobjs: the json objects or events to be ingested into splunk.
        :param table: the servicenow table from which data is to be collected.
        :param timefield: the field used to checkpoint the modular input.
        :param input_name: the name of the input configured.
        :param host: the host to be assigned to the collected events.
        :param excludes: param to format events in _ObjectWrapper class.
        """ 

        _LOGGER.debug("Proceeding to add events to Event Queue.")

        objs = []
        objs.extend((_ObjectWrapper(obj, table, self.host, timefield, input_name)
                        for obj in jobjs))
        results = {table: objs}
        event_queue = self.config["event_queue"]
        for _, data_objs in results.items():

            if data_objs:
                events = "".join(("<stream>%s</stream>"
                                    % obj.to_string(self.config.get("index", "default"), host, excludes)
                                    for obj in data_objs))
                event_queue.put(events)
        _LOGGER.debug("Events successfully written to the Event Queue.")


    def _do_collect(self, table, params, next_offset, limit):
        rest_uri = self._get_uri(table, params, next_offset, limit)

        http = rest.build_http_connection(
            self.config, self.config["duration"])
        response, content = None, None
        try:
            for retry in range(3):
                if retry > 0:
                    _LOGGER.info("Retry count: {}/3".format(retry + 1))
                _LOGGER.info("Initiating request to {}".format(rest_uri))
                if self.auth_type == "basic":
                    credentials = base64.urlsafe_b64encode(("%s:%s" % (self.config["username"], 
                                                                        self.config["password"])).encode('UTF-8')).decode('ascii')
                    response, content = http.request(rest_uri, headers={
                        "Accept-Encoding": "gzip",
                        "Accept": "application/json",
                        "Authorization": "Basic %s" % credentials
                    })
                else:
                    response, content = http.request(rest_uri, headers={
                        "Accept-Encoding": "gzip",
                        "Accept": "application/json",
                        "Authorization": "Bearer %s" % self.oauth_access_token
                    })

                if response.status not in (200, 201):
                    _LOGGER.error("Failure occurred while connecting to {0}. The reason for failure={1}."
                                .format(rest_uri, response.reason))

                    # If HTTP status = 401, there is a possibility that access token is expired
                    if response.status == 401 and self.auth_type == "oauth":
                        _LOGGER.error("Failure potentially caused by expired access token. Regenerating access token.")
                        snow_oauth = soauth.SnowOAuth(self.config, "main")
                        update_status = snow_oauth.regenerate_oauth_access_tokens()

                        if update_status:
                            token_details = snow_oauth.get_account_oauth_tokens(self.config["session_key"] ,self.account)

                            # Reloading the class variables with the new tokens generated
                            self.oauth_access_token = token_details["access_token"]
                            self.oauth_refresh_token = token_details["refresh_token"]
                            self.config.update({
                                "access_token": token_details["access_token"],
                                "refresh_token": token_details["refresh_token"]
                            })

                            continue
                        else:
                            _LOGGER.error("Unable to generate a new access token. Failure potentially caused by "
                                            "the expired refresh token. To fix the issue, reconfigure the account.")
                            break
                    # Error is not related to access token expiration. Hence breaking the loop
                    else:
                        break
                # Response obtained successfully. Hence breaking the loop
                else:
                    break

        except Exception:
            _LOGGER.error("Failure occurred while connecting to {0}. The reason for failure={1}."
                          .format(rest_uri, traceback.format_exc()))
        
        _LOGGER.info("Ending request to {}".format(rest_uri))
        return response, content

    @staticmethod
    def _json_to_objects(json_str):
        json_str = json_str.decode()
        json_object = {}
        try:
            json_object = json.loads(json_str)
        except ValueError :
            _LOGGER.error("Obtained an invalid json string while parsing. Got value of type {}. Traceback : {}".format(type(json_str),traceback.format_exc()))
            raise ValueError("Received an invalid JSON string while parsing.")
        except Exception :
            _LOGGER.error("Error occured while parsing json string. Got value of type {} . The reason for failure= {}".format(type(json_str),traceback.format_exc()))

        return json_object

    def _remove_collected_records(self, last_time_records, jobjs):
        """
        This method removes records already collected in the last run before the upgrade
        from addon version 6.0.1 or earlier.
        :param last_time_records: list of values id_field of lastest timestamp records collected in last before upgrade.
        :param jobjs: the json objects or events to be ingested into splunk 
        :return last_time_records: list of values id_field of lastest timestamp records collected in last before upgrade.
        :return jobjs: the json objects or events to be ingested into splunk 
        """ 

        records_to_be_removed = []

        for obj in jobjs:
            if obj[self.id_field] in last_time_records:
                records_to_be_removed.append(obj[self.id_field])
        
        if records_to_be_removed:
            _LOGGER.debug("Duplicate records found : {}".format(records_to_be_removed))
            jobjs = [jobj for jobj in jobjs if jobj[self.id_field] not in records_to_be_removed]
            last_time_records = [last_time_record for last_time_record in last_time_records\
                if last_time_record not in records_to_be_removed]
            _LOGGER.debug("Removed duplicate records.")
        return last_time_records, jobjs

    def _get_uri(self, table, params, next_offset, limit):

        endpoint = ("api/now/table/{}?sysparm_display_value={}"
                        "&sysparm_offset={}&sysparm_limit={}").format(table, self._display_value, next_offset, limit)
        if self.filter_data:
            self.filter_data = self.filter_data.replace("&", "^").replace("|", "^OR")

        if self.include_list:
            combine_list = self.id_field.replace(" ", "").split(",")
            combine_list.extend((self.config.get("timefield") or "sys_updated_on").replace(" ", "").split(","))
            
            # when the process reboots, include_list is str, and otherwise a list
            self.include_list = self.include_list.split(",") if isinstance(self.include_list, str)\
                                         else self.include_list
            self.include_list = [item for item in self.include_list if item not in combine_list ]
            self.include_list.extend(combine_list)

            endpoint = "".join((endpoint, "&sysparm_fields=", ",".join(self.include_list)))

        if params:
            if self.filter_data:
                params = ("&sysparm_exclude_reference_link=true"
                        "&sysparm_query={}^{}").format(self.filter_data, params)

            else:
                params = ("&sysparm_exclude_reference_link=true"
                        "&sysparm_query={}").format(params)
        if params is None:
            if self.filter_data:
                params = ("&sysparm_exclude_reference_link=true"
                        "&sysparm_query={}").format(self.filter_data)

            else:
                params = ""
        rest_uri = "".join((self.host, endpoint, params))
        return rest_uri


    def _read_last_collection_time_and_offset(self, input_name, timefield):
        checkpoint_file_name = ".".join((input_name, timefield))
        if not self.context.get(checkpoint_file_name, None):
            _LOGGER.debug("Checkpoint file {} not in cache, reloading from checkpoint file".format(checkpoint_file_name))
            ckpt = self._read_last_checkpoint(checkpoint_file_name)
            if not ckpt:
                self.context[checkpoint_file_name] = {"last_collection_time": self.since_when, "next_offset": 0}

        return self.context[checkpoint_file_name]["last_collection_time"].replace(" ", "+"), self.context[checkpoint_file_name].get("next_offset", 0)


    def _read_last_checkpoint(self, input_name):
        fname = op.join(self.checkpoint_dir, input_name)
        if not op.isfile(fname):
            _LOGGER.debug("Checkpoint file not found for the input. Will use configured start date")
            return None
        try:
            with open(fname) as f:
                ckpt = json.load(f)
                assert ckpt["version"] == 1
                self.context[input_name] = ckpt
                return ckpt
        except Exception:
            _LOGGER.error("Error while reading last checkpoint. {}".format(
                traceback.format_exc()))
            return None

    def _write_checkpoint(self, input_name, timefield, jobjs):

        if jobjs and not jobjs[-1].get(timefield):
            _LOGGER.error("'{}' field is not found in the data collected for '{}' input. "
                          "In order to resolve the issue, provide valid value in 'Time field of the table' on Inputs page, or "
                          "edit 'timefield' parameter for the affected input in inputs.conf file."
                          .format(timefield, input_name))
            return 0

        checkpoint_file_name = ".".join((input_name, timefield))
        _LOGGER.debug("Proceeding to write checkpoint for input: {}".format(input_name))
        fname = op.join(self.checkpoint_dir, checkpoint_file_name)

        try:
            with open(fname, "w") as f:
                ckpt = {
                    "version": 1,
                    "last_collection_time": self.context[checkpoint_file_name]["last_collection_time"],
                    "next_offset": self.context[checkpoint_file_name]["next_offset"]
                }
                if self.context[checkpoint_file_name].get("last_time_records"):
                    ckpt["last_time_records"] = self.context[checkpoint_file_name]["last_time_records"]

                json.dump(ckpt, f)

            self.context[checkpoint_file_name] = ckpt
            _LOGGER.debug("Checkpoint written successfully for input: {}".format(input_name))
            return 1

        except Exception:
            _LOGGER.error("Error while writing checkpoint for input {}. {}".format(
                input_name,
                traceback.format_exc()))

    def is_alive(self):
        return 1
