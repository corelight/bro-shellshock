#signature shellshock-http {
#	ip-proto == tcp
#	http-request /.*\(\) \{/
#
#	eval ShellShock::http_request_sig_match
#}

signature shellshock-http-header {
	ip-proto == tcp
	http-request-header /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/

	eval ShellShock::http_header_sig_match
}