ShellShock Detector for Bro
===========================

This script detects successful exploitation of the Bash vulnerability
with CVE-2014-6271 nicknamed "ShellShock".  It's more comprehensive than
most of the detections around in that it's watching for behavior from 
the attacked host that might indicate successful compromise or actual
vulnerability.

If a host is seen receiving an attack over HTTP, Bro will watch for that
host to either download a dropper payload or send an ICMP ping.  Many
more mechanisms could show up, but this would cover most of the existing
known response mechanisms.  This script is configured by default to 
watch for files of mime type application/x-executable which would cover
the dropper listed in the attack here:

	https://gist.github.com/anonymous/929d622f3b36b00c0be1

Alternately if attackers are just testing with a ping command, this script
will watch for a ping command from the victim shortly after an
attack is detected.

This script will also add a tag to the "tags" field in the HTTP log for
any requests that appear to be possible attacks.  The content of the 
tag is: ShellShock::HIT.

For what it's worth, this script is cluster-aware and should work on
Bro clusters just fine and should be ok to run operationally.

Demo
----

This repository includes an example packet capture that exploits an 
example server named exploit.pcap.  Here are the relevant logs that are output.

notice.log

	#separator \x09
	#set_separator	,
	#empty_field	(empty)
	#unset_field	-
	#path	notice
	#open	2014-09-25-13-46-45
	#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for	dropped	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
	#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	interval	bool	string	string	string	double	double
	1411666207.588581	-	-	-	-	-	-	-	-	-	ShellShock::Exploit	High likelyhood of successful CVE-2014-6271 exploitation against 10.246.50.6.	Sent a ping to 10.246.50.2 within 0.000 seconds of an attack.	10.246.50.6	-	-	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
	#close	2014-09-25-13-46-45


http.log

	#separator \x09
	#set_separator	,
	#empty_field	(empty)
	#unset_field	-
	#path	http
	#open	2014-09-25-13-46-45
	#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	filename	tags	username	password	proxied	orig_fuids	orig_mime_types	resp_fuids	resp_mime_types
	#types	time	string	addr	port	addr	port	count	string	string	string	string	string	count	count	count	string	count	string	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]
	1411666207.583791	CRyZah1yxhmar8Xsje	10.246.50.2	43616	10.246.50.6	80	1	GET	10.246.50.6	/exploitable.cgi	-	() { :;}; /bin/ping -c1 10.246.50.2	0	615	500	Internal Server Error	-	-	-	ShellShock::HIT	-	-	-	-	-	FgVgjb1GU12ixSuugc	text/html
	#close	2014-09-25-13-46-45


Installation
------------

This repository uses the module loading mechanism in Bro so you can simply 
load this whole directory.  The directions below reflect that model of loading
the shellshock detector.

	cd <prefix>/share/bro/site
	git clone --recursive https://github.com/broala/bro-shellshock.git shellshock
	echo "@load shellshock" >> local.bro

Author
------

	Seth Hall <seth@broala.com>

Thanks
------

	Stephen Hosom - for providing a fully exploiting packet capture.



