
@load base/frameworks/notice
@load base/protocols/http
@load-sigs ./shellshock-http.sig

module ShellShock;

export {
	redef enum Notice::Type += {
		## Indicates a high likelyhood of successful shellshock exploitation.
		Exploit
	};

	redef enum HTTP::Tags += {
		HIT
	};

	## This contains a list of MIME types that would typically be
	## seen as droppers after the exploitation of ShellShock.
	const post_exploit_file_types: set[string] = {
		"application/x-executable", ##< elf executables (and some others)
		"application/x-dosexec",    ##< windows executables in case someone is exploiting cygwin
	} &redef;

	## The pattern for matching shellshock attacks.  This is 
	## also defined separately in the .sig file.
	const matcher = /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/ &redef;
}

redef Signatures::actions += {
	["shellshock-http"] = Signatures::SIG_IGNORE
};

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="shellshock.possible_http_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	local r2 = SumStats::Reducer($stream="shellshock.possible_dhcp_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	local r3 = SumStats::Reducer($stream="shellshock.possible_post_exploit_file", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	local r4 = SumStats::Reducer($stream="shellshock.possible_post_exploit_ping", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	SumStats::create([$name="look-for-shellshock",
	                  $epoch=5mins,
	                  $reducers=set(r1, r2, r3, r4),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
	                  	{
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	return exploit_ping$num + exploit_file$num + 0.0;
	                  	},
	                  $threshold = 1.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local http_attacks = result["shellshock.possible_http_victim"];
	                  	local dhcp_attacks = result["shellshock.possible_dhcp_victim"];
	                  	local total_attacks = http_attacks$num + dhcp_attacks$num;
	                  	
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	if ( total_attacks > 0 )
	                  		{
	                  		local attack_msg = "Attack over";
	                  		local exploit_msg = "";
	                  		local attack_time: time;
	                  		if ( http_attacks$num > 0 )
	                  			{
	                  			attack_msg = fmt("%s HTTP", attack_msg);
	                  			attack_time = http_attacks$begin;
	                  			}
	                  		else if ( dhcp_attacks$num > 0 )
	                  			{
	                  			attack_msg = fmt("%s DHCP", attack_msg);
	                  			attack_time = dhcp_attacks$begin;
	                  			}

	                  		if ( exploit_file$num > 0 )
	                  			{
	                  			exploit_msg = fmt("requested a potential dropper within %.3f seconds of an attack", exploit_file$begin-attack_time);
	                  			}
	                  		if ( exploit_ping$num > 0 )
	                  			{
	                  			if ( exploit_msg != "" )
	                  				exploit_msg += " and ";

	                  			local ping_dst = SumStats::get_last(exploit_ping)[0]$str;
	                  			exploit_msg = fmt("%ssent a ping to %s within %.3f seconds of an attack.", exploit_msg, ping_dst, exploit_ping$begin-attack_time);
	                  			}

	                  		NOTICE([$note=Exploit,
	                  		        $src=key$host,
	                  		        $msg=fmt("High likelyhood of successful CVE-2014-6271 exploitation against %s.", key$host),
	                  		        $sub=fmt("%s and %s", attack_msg, exploit_msg),
	                  		        $identifier=cat(key$host)]);
	                  		}
	                  	}]);
	}


function ShellShock::http_header_sig_match(state: signature_state, data: string): bool
	{
	local c = state$conn;
	if ( c?$http )
		add c$http$tags[ShellShock::HIT];

	SumStats::observe("shellshock.possible_http_victim", [$host=c$id$resp_h], [$str=data]);
	return F;
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
	{
	if ( matcher in host_name )
		{
		SumStats::observe("shellshock.possible_dhcp_victim", [$host=c$id$resp_h], [$str=host_name]);
		}
	}

function ShellShock::http_request_sig_match(state: signature_state, data: string): bool
	{
	local c = state$conn;
	if ( c?$http )
		add c$http$tags[ShellShock::HIT];

	SumStats::observe("shellshock.possible_http_victim", [$host=c$id$resp_h], [$str=data]);
	return F;
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f?$mime_type && f$mime_type in post_exploit_file_types )
		{
		local host = is_orig ? c$id$resp_h : c$id$orig_h;
		SumStats::observe("shellshock.possible_post_exploit_file", [$host=host], [$str=f$mime_type]);
		}
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("shellshock.possible_post_exploit_ping", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
	}

