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
	RANDOMNESS:		con 1000;

	# DHT messages
	TPing,			# 100
	RPing,
	TStore,			# 102
	RStore,
	TFindValue,		# 104
	RFindValue,
	TFindNode,		# 106
	RFindNode,
	Tmax: con 100+iota;

	# DHT functions error codes
	EBucketFull,
	EAlreadyPresent,
	EMax: con 100+iota;

	Key: adt {
		data: array of byte;
        
		text: fn(nil: self ref Key): string;
		generate: fn(): Key;
        lt: fn(nil: self ref Key, other: ref Key): int;
        gt: fn(nil: self ref Key, other: ref Key): int;
	};

	Node: adt {
		id: Key;
		addr: string;
		rtt: int;		# round-trip time

		text: fn(nil: self ref Node): string;
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
			key: Key;
		FindValue =>
			key: Key;
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

	Bucket: adt {
		nodes: array of Node;
		minrange: int;
		maxrange: int;
		lastaccess: Daytime->Tm;

		isinrange: fn(nil: self ref Bucket, id: Key): int;
		addnode: fn(nil: self ref Bucket, n: Node): int;
		getnodes: fn(nil: self ref Bucket, size: int): array of Node;
		findnode: fn(nil: self ref Bucket, id: Key): int;
        print: fn(nil: self ref Bucket, tabs: int); #TODO
	};

	Contacts: adt {
        buckets: array of Bucket;
        localid: Key;

        addcontact: fn(nil: self ref Contacts, n: ref Node); 
        removecontact: fn(nil: self ref Contacts, id: Key); 
        getnode: fn(nil: self ref Contacts, id: Key): ref Node;
        findclosenodes: fn(nil: self ref Contacts, id: Key): array of Node;
        touch: fn(nil: self ref Contacts, idx: int);
        findbucket: fn(nil: self ref Contacts, id: Key): int; 
        split: fn(nil: self ref Contacts, idx: int); 
        randomidinbucket: fn(nil: self ref Contacts, idx: int): Key; 
        print: fn(nil: self ref Contacts, tabs: int);
	};

	Local: adt {
		node: Node;
		contacts: Contacts;
		# store consists of Key, data and last access time
		store: list of (Key, array of byte, Daytime->Tm);

		# private data
		timerpid, processpid: int;

		# do some periodic processing
		process: fn(nil: self ref Local, conn: Sys->Connection);
		# fire the event with some interval
		timer: fn (nil: self ref Local);
		# finish all internal threads and close the server
		destroy: fn(nil: self ref Local);
	};

	init:	fn();
	start:	fn(localaddr: string, bootstrap: ref Node, id: Key): ref Local;

};
