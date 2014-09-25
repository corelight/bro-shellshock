
@load base/frameworks/notice
@load base/protocols/http
@load-sigs ./shellshock-http.sig

module ShellShock;

export {
	redef enum Notice::Type += {
		## Indicates a high likelyhood of successful shellshock exploitation.
		Exploit
	};

	const post_exploit_file_types: set[string] = {
		"application/x-dosexec"
	} &redef;

	redef enum HTTP::Tags += {
		HIT
	};
}

redef Signatures::actions += {
	["shellshock-http"] = Signatures::SIG_IGNORE
};

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="shellshock.possible_http_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	local r2 = SumStats::Reducer($stream="shellshock.possible_post_exploit_file", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	local r3 = SumStats::Reducer($stream="shellshock.possible_post_exploit_ping", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=2);

	SumStats::create([$name="look-for-shellshock",
	                  $epoch=5mins,
	                  $reducers=set(r1, r2, r3),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
	                  	{
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	return exploit_ping$num + exploit_file$num + 0.0;
	                  	},
	                  $threshold = 1.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local attacks = result["shellshock.possible_http_victim"];
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	if ( attacks$num > 0 )
	                  		{
	                  		local sub_msg = "";
	                  		if ( exploit_file$num > 0 )
	                  			{
	                  			sub_msg = fmt("Requested a potential dropper within %.3f seconds of an attack", exploit_file$begin-attacks$begin);
	                  			}
	                  		if ( exploit_ping$num > 0 )
	                  			{
	                  			if ( sub_msg != "" )
	                  				sub_msg += " and ";

	                  			local ping_dst = SumStats::get_last(exploit_ping)[0]$str;
	                  			sub_msg = fmt("%sSent a ping to %s within %.3f seconds of an attack.", sub_msg, ping_dst, exploit_ping$begin-attacks$begin);
	                  			}

	                  		NOTICE([$note=Exploit,
	                  		        $src=key$host,
	                  		        $msg=fmt("High likelyhood of successful CVE-2014-6271 exploitation against %s.", key$host),
	                  		        $sub=sub_msg,
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
