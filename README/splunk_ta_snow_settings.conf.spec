##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-1-2020
##
##

[proxy]
proxy_enabled = <bool> Enable or disable proxy.
proxy_url = <string> Proxy URL.
proxy_port = <integer> Port for configuring proxy.
proxy_username = <string> Username for configuring proxy.
proxy_password = <string> Password for configuring proxy.
proxy_rdns = <bool> Remote DNS resolution.
proxy_type = <string> Proxy type (http, http_no_tunnel, socks4, socks5). 

[logging]
loglevel = <string> Select log level.

[additional_parameters]
create_incident_on_zero_results = <bool> Specifies whether to create incident on 0 search results or not.