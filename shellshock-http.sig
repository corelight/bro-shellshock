#signature shellshock-http {
#	ip-proto == tcp
#	http-request /.*\(\) \{/
#
#	eval ShellShock::http_request_sig_match
#}

signature shellshock-http-header {
	ip-proto == tcp
	http-request-header /.*\(\) \{/

	eval ShellShock::http_header_sig_match
}