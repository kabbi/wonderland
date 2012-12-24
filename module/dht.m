Dht: module
{
	PATH:	con "/dis/lib/dht.dis";

	BIT8SZ:	con 1;
	BIT16SZ:	con 2;
	BIT32SZ:	con 4;
	BIT64SZ:	con 8;

	IOHDRSZ:	con 70;	# room for Tmsg/Rmsg header
	MAXFDATA: con 8192;	# `reasonable' iounit
	MAXRPC:	con IOHDRSZ+MAXFDATA;	# usable default for fversion and iounit

	# The code below comes mostly from the Kademlia specs
	# see http://xlattice.sourceforge.net/components/protocol/kademlia/specs.html
	# or http://www.freezepage.com/1350050954SJTTPDWBEX

	# DHT constants
	ALPHA:	con 1;
	B:		con 32;
	BB:		con B/8; # B in bytes
	K:		con 5;
	EXPIRE_TIME:	con 86410;	# 86410
	REFRESH_TIME:	con 10;		# 3600
	REPLICATE_TIME:	con 3600;	# 3600
	REPUBLISH_TIME: con 86400;	# 86400
	RANDOMNESS:		con 1000;	# 1000

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

	# FindValue result codes
	FVNodes,
	FVValue,
	FVMax: con iota;

	# Store result codes
	SSuccess,
	SFail: con iota;

	Node: adt {
		id: Key;
		addr: string;
		rtt: int;		# round-trip time

		text: fn(nil: self ref Node): string;
	};

	StoreItem: adt {
		data: array of byte;
		lastupdate: int;
		publishtime: int;

		eq: fn(a, b: ref StoreItem): int;
	};

	# DHT message handlers
	Tmsg: adt {
		uid: Key;
		remoteaddr: string;
		senderID: Key;
		targetID: Key;
		pick {
		Ping =>
			# no additional data
		Store =>
			key: Key;
			value: ref StoreItem;
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
		uid: Key;
		remoteaddr: string;
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
			nodes: array of Node;
			value: list of ref StoreItem;
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
		minrange: Key;
		maxrange: Key;
		lastaccess: int;

		isinrange: fn(nil: self ref Bucket, id: Key): int;
		addnode: fn(nil: self ref Bucket, n: ref Node): int;
		getnodes: fn(nil: self ref Bucket, size: int): array of Node;
		findnode: fn(nil: self ref Bucket, id: Key): int;
        print: fn(nil: self ref Bucket, tabs: int); 
	};

	Contacts: adt {
        buckets: array of ref Bucket;
        local: cyclic ref Local;

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
		contacts: cyclic ref Contacts;
		# store consists of Key, data and last access time
		store: ref HashTable[list of ref StoreItem];
		ourstore: ref HashTable[list of ref StoreItem];

		# public API
		dhtfindnode: fn(nil: self ref Local, id: Key, nodes: array of ref Node): ref Node;
		dhtfindvalue: fn(nil: self ref Local, id: Key): list of ref StoreItem;
		dhtstore: fn(nil: self ref Local, key: Key, data: array of byte);
		# returns the rtt, or -1 if node is not reachable
		# raises exception if node is not found (??)
		dhtping: fn(nil: self ref Local, id: Key): int;
		# sets the file descriptor for logs, if nil logging is turned off
		setlogfd: fn(nil: self ref Local, fd: ref Sys->FD);

		# private data and methods
		callbacks: ref HashTable[chan of ref Rmsg];
		timerpid, processpid, syncpid: int;
		logfd: ref Sys->FD;
		conn: Sys->Connection;
		sync: chan of int;

		# do some periodic processing
		process: fn(nil: self ref Local);
		# find k closest nodes to the given one
		findkclosest: fn(nil: self ref Local, id: Key): array of ref Node;
		# process some message
		processrmsg: fn(nil: self ref Local, buf: array of byte);
		processtmsg: fn(nil: self ref Local, buf: array of byte);
		# send the message and setup callback with given channel
		sendtmsg: fn(nil: self ref Local, n: ref Node, msg: ref Tmsg): chan of ref Rmsg;
		# same as above, but without callbacks
		sendrmsg: fn(nil: self ref Local, n: ref Node, msg: ref Rmsg);
		# log some data
		logevent: fn(nil: self ref Local, source: string, msg: string);
		# fire the event with some interval
		timer: fn (nil: self ref Local);
		# the thing that would sync everything
		syncthread: fn (nil: self ref Local);
		# finish all internal threads and close the server
		destroy: fn(nil: self ref Local);
	};

	init:	fn();
	start:	fn(localaddr: string, bootstrap: array of ref Node, id: Key): ref Local;

};
