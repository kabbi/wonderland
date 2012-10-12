Dht: module
{
	PATH:	con "/dis/lib/dht.dis";

	BIT8SZ:	con 1;
	BIT16SZ:	con 2;
	BIT32SZ:	con 4;
	BIT64SZ:	con 8;

	IOHDRSZ:	con 24;	# room for Twrite/Rread header
	MAXFDATA: con 8192;	# `reasonable' iounit
	MAXRPC:	con IOHDRSZ+MAXFDATA;	# usable default for fversion and iounit

	# The code below comes mostly from the Kademlia specs
	# see http://xlattice.sourceforge.net/components/protocol/kademlia/specs.html
	# or http://www.freezepage.com/1350050954SJTTPDWBEX

	# DHT constants
	ALPHA:	con 3;
	B:		con 160;
	BB:		con B/8; # B in bytes
	K:		con 20;
	EXPIRE_TIME:	con 86410;
	REFRESH_TIME:	con 3600;
	REPLICATE_TIME:	con 3600;
	REPUBLISH_TIME: con 86400;

	# DHT messages
	TPing,			# 100
	Rping,
	TStore,			# 102
	RStore,
	TFindValue,		# 104
	RFindValue,
	TFindNode,		# 106, illegal
	RFindNode,
	Tmax: con 100+iota;

	Key: adt {
		data: array [BB] of byte;

		text: fn(nil: self ref Key): string;
		generate: fn(): ref Key;
	};

	Node: adt {
		id: Key;
		addr: string;
		rtt: int;		# round-trip time
	};

	# DHT message handlers
	Tmsg: adt {
		tag: int;
		senderID: Key;
		targetID: Key;
		pick {
		Ping =>
			# no additional data
		Store =>
			key: Key;
			data: array of byte;
			# to allow two-stage STORE
			ask: int;
		FindNode =>
			# no additional data
		FindValue =>
			# no additional data
		}

		read:	fn(fd: ref Sys->FD, msize: int): ref Tmsg;
		unpack:	fn(a: array of byte): (int, ref Tmsg);
		pack:	fn(nil: self ref Tmsg): array of byte;
		packedsize:	fn(nil: self ref Tmsg): int;
		text:	fn(nil: self ref Tmsg): string;
		mtype:	fn(nil: self ref Tmsg): int;
	};

	Rmsg: adt {
		tag: int;
		senderID: Key;
		targetID: Key;
		pick {
		Ping =>
			# no additional data
		Store =>
			result: int;
		FindNode =>
			nodes: array of Node;
		FindValue =>
			result: int;
			nodes: array of Node;
			value: array of byte;
		}

		read:	fn(fd: ref Sys->FD, msize: int): ref Rmsg;
		unpack:	fn(a: array of byte): (int, ref Rmsg);
		pack:	fn(nil: self ref Rmsg): array of byte;
		packedsize:	fn(nil: self ref Rmsg): int;
		text:	fn(nil: self ref Rmsg): string;
		mtype:	fn(nil: self ref Rmsg): int;
	};

	Contacts: adt {
		table: array [K] of (list of Nodes);
	};

	Local: module {
		node: Node;
		contacts: Contacts;
		# store consists of Key, data and last 
		store: list of (Key, array of byte, Daytime->Tm);
	};

	init:	fn();
	start:	fn(dht: ref Dht, localaddr: string, bootstrap: list of Node, id: Key): ref Local;

};
