##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

ta_frmk = "ta_frmk"
ta_frmk_conf = "ta_frmk_conf"
ta_frmk_rest = "ta_frmk_rest"
ta_frmk_state_store = "ta_frmk_state_store"
ta_frmk_rh_oauth = "splunk_ta_snow_rh_oauth2_token"


def get_all_logs():
    g = globals()
    return [g[log] for log in g if log.startswith("ta_")]
