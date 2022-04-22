# Add MSS and SACK information to the conn.log

redef record Conn::Info += {
	mss: count &optional &log;
	sack_ok: bool &optional &log;
};

redef record connection += {
	mss: count &optional &log;
	sack_ok: bool &optional &log;
};

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
	c$mss = pkt$MSS;
	c$sack_ok = pkt$SACK_OK;
}

event connection_state_remove(c: connection) {
	if ( c ?$ mss )
		c$conn$mss = c$mss;

	if (c ?$ sack_ok )
		c$conn$sack_ok = c$sack_ok;
}
