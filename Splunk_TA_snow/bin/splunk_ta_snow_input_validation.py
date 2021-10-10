##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

import re
from snow import valid_filter_data_format, validate_combined_length, special_character_validation, FIELD_VALIDATION_MESSAGE
import framework.log as log
from splunktaucclib.rest_handler.endpoint.validator import Validator
from datetime import datetime

APP_NAME = "Splunk_TA_snow"
_LOGGER = log.Logs().get_logger("main")


class DateValidator(Validator):
    """
    This class validates if the data passed for validation
     in input is in future.
    If so throws error in UI and logs
    """
    def __init__(self, *args, **kwargs):
        super(DateValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        try:
            input_date = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            now = datetime.utcnow()
            if input_date > now:
                self.put_msg("Start date should not be in future", True)
                _LOGGER.error("Start date of the input should not be in future, but got '{}'".format(value))
                return False

        except ValueError as exc:
            self.put_msg(str(exc))
            _LOGGER.error("Start Date of the input should be in YYYY-DD-MM hh:mm:ss format, but got '{}'".format(value))
            return False
        return True

class IncludeFilterParameterValidator(Validator):
    """
    This class validates if the data passed for validation
    in input is in key1=value1&key2=value2|key3=value3 format.
    It also validates that the combined length of Filter Parameters
    and Included Properties is not more than 1000 characters.
    If not, throws error in UI and logs.
    """
    def __init__(self, *args, **kwargs):
        super(IncludeFilterParameterValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):

        length_of_url_parameters_combined = validate_combined_length(data.get("filter_data", ""), data.get("include", ""))
        if length_of_url_parameters_combined:
            error_message = ("The combined length of Filter Parameters and Included Properties is too long({})."
                    "The maximum permissible length is 1000 characters.").format(length_of_url_parameters_combined)
            self.put_msg(error_message, True)
            return False

        error_message = ("Filters should be in key1=value1&key2=value2|key3=value3 "
                "format for input, but got '{}'. Please refer to Splunk Add-on "
                "for ServiceNow documentation for additional information.").format(data.get("filter_data", ""))

        if data.get("filter_data") and not valid_filter_data_format(data.get("filter_data")):
            _LOGGER.error(error_message)
            self.put_msg(error_message, True)
            return False

        if data.get("include") and not special_character_validation(data.get("include")):
            self.put_msg(FIELD_VALIDATION_MESSAGE.format(data.get("include")), True)
            return False
        return True


class SpecialValidator(Validator):
    def __init__(self, *args, **kwargs):
        super(SpecialValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        if not special_character_validation(value):
            self.put_msg(FIELD_VALIDATION_MESSAGE.format(value), True)
            return False
        return True
