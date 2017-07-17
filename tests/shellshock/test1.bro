# @TEST-EXEC: bro -r $TRACES/exploit.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load ../../../scripts

event Notice::log_notice(rec: Notice::Info)
	{
	print rec$msg;
	}
