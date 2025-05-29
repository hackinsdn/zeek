
module DNSTunnelEstablishment;

#!/usr/local/zeek/share/zeek/policy/protocols/dnstunnel

@load base/frameworks/logging

export {

	## A default logging policy hook for the stream.
	#global log_policy: Log::PolicyHook;
	
	global counter = 0;
	
	#global total_entropy: double = 0.0;
	#global total_queries: double = 0.0;

	## The DNS Tunnel logging stream identifier.
   	## Append the value LOG to the Log::ID enumerable.
	redef enum Log::ID += { LOG };
	
	type Info: record{
		
		ctime: time &log;
		
		uid: string &log;  
		
		id: conn_id &log;  
		
		clen: count &log;
		
		mlen: count &log &optional;
		
		alen: count &log &optional;
		
		ptype: string &log &optional;
		
		query: string &log &optional;
		
		entropy: double &log &optional;

		
		};

	}


event zeek_init() &priority=3
	{
	#Create the logging stream
	Log::create_stream(LOG, [$columns=Info, $path="dns_tunnel_establishment"]);

	}
	
#event DNSTunnelling::message(c: connection, is_orig: bool, payload: string) &priority=5
#{
#	Log::write( DNSTunnelEstablishment::LOG, [$ctime=current_time(), $uid=c$uid, $id=c$id, $clen=|c|]);
#}

#event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=3


function entropy(data: string):double
	{
	local result = 0.0;
	local words: vector of string;
	local repetition: vector of string;
	local total = vector(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);


	for (d in data)
		{
		
		words += d;
		
		}
	for (a in words)
	{
		if (|repetition|==0)
		{
			repetition += words[0];
			total[0]+=1;
		}
		else
		{
			counter=0;
			for (b in repetition) {
				
				if (repetition[b]==words[a])
					{
						total[b]+=1;
						counter=1;
						break;
					
					}
					
				else {
				
					#print fmt("%s!=%s",repetition[b],words[a]);
				}
			}
			if (counter==0){
				repetition+=words[a];
				#print words[a];
				total[|repetition|]+=1;

			}
		
		}
		
	}
	
	
	for (c in total)
		{
		if (total[c]>0){
		#print total[c];
		}
		}
	for (c in repetition){
		#print repetition[c];
	}
	
	for (t in total){
		if (total[t]>=1)
		{
		local freq: double;
		local qtt: double;
		local len: double;
		len = |data|;
		qtt = total[t];
		freq=0.0;
		freq = ((qtt)/(len));
		#print freq, qtt,len;
		result += ((freq)*(log2(freq)))*(-1);
		#print result;
		}
		}
	

	
		
	#result = result * (-1);
	
	return result;
	
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=3

{
	local entropy_result = entropy(query);
	
	#total_entropy += entropy(query);
	#total_queries += 1;
	
	if (entropy_result >= 3.8){
	Log::write( DNSTunnelEstablishment::LOG, [$ctime=current_time(), $uid=c$dns$uid, $id=c$dns$id, $clen=|c|, $mlen=|msg|, $ptype="REQUEST", $query=c$dns$query, $entropy=entropy_result]);	
	}
	}


#event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
#	{
#	
#	Log::write( DNSTunnel::LOG, [$ctime=current_time(), $uid=c$dns$uid, $id=c$dns$id, $clen=|c|, $mlen=|msg|, $ptype="UNK_ANSWER", #$query=c$dns$query]);	
#	
#	
#	}
	
	
#event zeek_done()
#	{
#	print total_entropy;
#	print total_queries;
#	
#	}
