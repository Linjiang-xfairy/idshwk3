global http_dict : table[addr] of set[string] = table();

#this function will count the element numbers in set:IPtoUA.
function length_stat(IPtoUA: set[string]):int {
	local re:int = 0;
	for(i in IPtoUA) {
		re += 1;
	}
	return re;
}

#At http_header event, it will work out the statistics of relationship between src-ip and user-agent, being stored at table http_dict(global value).
event http_header(c: connection, is_orig: bool, name: string, value: string){
	if(name == "USER-AGENT") {
		if(c$id$orig_h in http_dict) {
			add http_dict[c$id$orig_h][to_lower(value)];
		}
		else {
			http_dict[c$id$orig_h] = set(to_lower(value));
		}
	}
}

#At zeek_done event, it will work out the src-ip which related to three UA or more.
event zeek_done() {
	for(i in http_dict) {
		if(length_stat(http_dict[i]) >= 3) {
			print fmt("%s is a proxy", i);
		}
	}
}
