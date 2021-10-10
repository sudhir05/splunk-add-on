##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##


import import_declare_test

from solnlib.splunkenv import make_splunkhome_path
from framework import state_store as ss

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunk_ta_snow_input_validation import DateValidator, IncludeFilterParameterValidator, SpecialValidator
import logging
import framework.log as log
from datetime import datetime
from datetime import timedelta

util.remove_http_proxy_env_vars()
_LOGGER = log.Logs().get_logger("main")

fields = [
    field.RestField(
        'account',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'duration',
        required=True,
        encrypted=False,
        default=60,
        validator=validator.Number(
            max_val=31536000, 
            min_val=1, 
        )
    ), 
    field.RestField(
        'table',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'include',
        required=False,
        encrypted=False,
        default=None,
        validator=IncludeFilterParameterValidator()
    ), 
    field.RestField(
        'exclude',
        required=False,
        encrypted=False,
        default=None,
        validator=SpecialValidator()
    ), 
    field.RestField(
        'timefield',
        required=False,
        encrypted=False,
        default='sys_updated_on',
        validator=SpecialValidator()
    ), 
    field.RestField(
        'reuse_checkpoint',
        required=False,
        encrypted=False,
        default='yes',
        validator=None
    ), 
    field.RestField(
        'since_when',
        required=False,
        encrypted=False,
        default=None,
        validator=DateValidator()
    ), 
    field.RestField(
        'id_field',
        required=False,
        encrypted=False,
        default='sys_id',
        validator=SpecialValidator()
    ), 
    field.RestField(
        'filter_data',
        required=False,
        encrypted=False,
        default=None,
        validator=IncludeFilterParameterValidator()
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    ),
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            min_len=1, 
            max_len=80, 
        )
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'snow',
    model,
)

class SnowHandler(AdminExternalHandler):
    """
    Manage Snow Data Input Details.
    """
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    @staticmethod
    def get_session_key(self):
        return self.getSessionKey()

    def deleteCheckpoint(self, ckpt_name):
        session_key = self.get_session_key(self)
        appname = "Splunk_TA_snow"
        metadata = {
            'checkpoint_dir': make_splunkhome_path(["var", "lib", "splunk", "modinputs", "snow"]),
            'session_key': session_key
        }
        state = ss.StateStore(metadata, appname)
        checkpoint_data = state.get_state(ckpt_name)

        if checkpoint_data:
            state.delete_state(ckpt_name)

    def checkReuseCheckpoint(self):
        # Check the reuse_checkpoint field. If it's value is 'no', delete it's checkpoint if present.
        if self.payload.get('reuse_checkpoint') == 'no':
            input_name = self.callerArgs.id
            timefield = self.payload.get("timefield") or "sys_updated_on"
            ckpt_name = input_name + "." + timefield
            self.deleteCheckpoint(ckpt_name)

        if 'reuse_checkpoint' in self.payload:
            del self.payload['reuse_checkpoint']

    def checkSinceWhen(self):
        now = datetime.utcnow() - timedelta(7)
        # Check if since_when field is empty. If so, set its default value to one week ago so that it reflects on UI.
        if not self.payload.get('since_when'):
            self.payload['since_when'] = datetime.strftime(now, "%Y-%m-%d %H:%M:%S") 

    def handleCreate(self, confInfo):
        self.checkReuseCheckpoint()
        self.checkSinceWhen()

        AdminExternalHandler.handleCreate(self, confInfo)

    def handleEdit(self, confInfo):        
        self.checkReuseCheckpoint()
        self.checkSinceWhen()

        AdminExternalHandler.handleEdit(self, confInfo)



if __name__ == '__main__':
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=SnowHandler,
    )
