Dht: module
{
    PATH:   con "/dis/lib/dht.dis";

    BIT8SZ: con 1;
    BIT16SZ:    con 2;
    BIT32SZ:    con 4;
    BIT64SZ:    con 8;

    IOHDRSZ:    con 70; # room for Tmsg/Rmsg header
    MAXFDATA: con 10000; # `reasonable' iounit (was 8192)
    MAXRPC: con IOHDRSZ+MAXFDATA;   # usable default for fversion and iounit

    # The code below comes mostly from the Kademlia specs
    # see http://xlattice.sourceforge.net/components/protocol/kademlia/specs.html
    # or http://www.freezepage.com/1350050954SJTTPDWBEX

    # DHT constants
    ALPHA:  con 2;
    B:      con 32;
    BB:     con B/8; # B in bytes
    K:      con 5; 
    EXPIRE_TIME:    con 300;    # 86410
    REFRESH_TIME:   con 60;     # 3600
    REPLICATE_TIME: con 3600;   # 3600
    REPUBLISH_TIME: con 60;     # 86400
    RANDOMNESS:     con 1000;   # 1000
    WAIT_TIME:      con 2000;   # 2000
    TKEEP_ALIVE:    con 10000;  # ?
    MAXRETRANSMIT:  con 5;

    # DHT messages
    TPing,          # 100
    RPing,
    TStore,         # 102
    RStore,
    TFindValue,     # 104
    RFindValue,
    TFindNode,      # 106
    RFindNode,
    TAskRandezvous, # 108
    RAskRandezvous,
    TInvitation,    # 110
    RInvitation,
    TObserve,       # 112
    RObserve,
    TUser,          # 114
    RUser,
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
    SFail,
    SSuccess: con iota;

    # AskRandezvous result codes
    RFail,
    RSuccess: con iota;

    # Callbacks channel actions
    QAddCallback,
    QRemoveCallback,
    # Store channel actions (maybe are not used)
    QAddItem,
    QRemoveItem,
    QUpdateItem,
    # Contacts channel actions
    QAddContact,
    QRemoveContact: con iota;

    # Query for rmsg return values
    QTimeOut: con (iota * -1);

    Node: adt {
        id: Key;
        prvaddr: string;
        pubaddr: string;
        srvaddr: string;
        srvid: Key;

        text: fn(nil: self ref Node): string;
        eq: fn(n1: ref Node, n2: ref Node): int;
    };

    StoreItem: adt {
        data: array of byte;
        lastupdate: int;
        publishtime: int;

        eq: fn(a, b: ref StoreItem): int;
    };

    Stats: adt {
        senttmsgs: int;                     # the total number of sent Tmsgs
        sentrmsgs: int;                     # the total number of sent Rmsgs
        recvdtmsgs: int;                    # the total number of received Tmsgs
        recvdrmsgs: int;                    # the total number of received Rmsgs
        processerrors: int;                 # the number of incoming message processing errors
        senderrors: int;                    # the number of errors during sending
        startuptime: int;                   # the time of dht startup
        sentmsgsbytype: array of int;       # the number of sends of every message
        recvmsgsbytype: array of int;       # the number of receives of every message
        findvaluecalled: int;               # the number of times dhtfindvalue was called
        findnodecalled: int;                # the number of times dhtfindnode was called
        pingcalled: int;                    # the number of times ping was called
        storecalled: int;                   # the number of times store was called
        totalrtt: int;                      # the sum of all rtts of all received answers
        answersgot: int;                    # the total number of received answers
        expiredentries: int;                # the number of expired store entries
        unanswerednodes: int;               # the number of unanswered nodes during bucket overflows
        bucketoverflows: int;               # the count of bucket overflows
        logentries: int;                    # the number of log entries emitted
    };

    # DHT message handlers
    Tmsg: adt {
        uid: Key;
        sender: Node;
        targetid: Key;
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
        AskRandezvous =>
            oppid: Key;
            addr: string;
        Invitation =>
            oppprvaddr: string;
            opppubaddr: string;
            oppid: Key;
        Observe =>
            # no data
        User =>
            data: array of byte;
        }

        read:   fn(fd: ref Sys->FD, msize: int): ref Tmsg;
        unpack: fn(a: array of byte): (int, ref Tmsg);
        pack:   fn(nil: self ref Tmsg): array of byte;
        packedsize: fn(nil: self ref Tmsg): int;
        text:   fn(nil: self ref Tmsg): string;
        mtype:  fn(nil: self ref Tmsg): int;
    };

    Rmsg: adt {
        uid: Key;
        senderid: Key;
        targetid: Key;
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
# TODO: remove if unused
        AskRandezvous =>
            result: int;
        Invitation =>
            result: int;
        Observe =>
            observedaddr: string;
        User =>
            data: array of byte;
        }

        read:   fn(fd: ref Sys->FD, msize: int): ref Rmsg;
        unpack: fn(a: array of byte): (int, ref Rmsg);
        pack:   fn(nil: self ref Rmsg): array of byte;
        packedsize: fn(nil: self ref Rmsg): int;
        text:   fn(nil: self ref Rmsg): string;
        mtype:  fn(nil: self ref Rmsg): int;
    };

    Bucket: adt {
        nodes: list of ref Node;
        minrange: Key;
        maxrange: Key;
        lastaccess: int;

        isinrange: fn(nil: self ref Bucket, id: Key): int;
        addnode: fn(nil: self ref Bucket, n: ref Node): int;
        getnodes: fn(nil: self ref Bucket, size: int): array of Node;
        removenode: fn(nil: self ref Bucket, id: Key);
        findnode: fn(nil: self ref Bucket, id: Key): ref Node;
        text: fn(nil: self ref Bucket, tabs: int): string; 
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
        text: fn(nil: self ref Contacts, tabs: int): string;
        getpublicnodes: fn(nil: self ref Contacts): array of ref Node;
    };

    Local: adt {
        node: Node;
        localaddr: (IPaddr, int);
        contacts: cyclic ref Contacts;
        # store consists of Key, data and last access time
        store: ref HashTable[list of ref StoreItem];
        ourstore: ref HashTable[list of ref StoreItem];
        # stats object, publically usable
        stats: ref Stats;
        usermsghandler: chan of (ref Tmsg.User);

        # private data and methods
        callbacksch: chan of (int, string, chan of ref Rmsg);
        callbacks: ref HashTable[chan of ref Rmsg];
        storech: chan of (string, ref StoreItem, ref StoreItem,
            ref HashTable[list of ref StoreItem]);
        contactsch: chan of (int, ref Node);
        timerpid, processpid, callbacksprocpid,
            contactsprocpid, storeprocpid: int;
        logfd: ref Sys->FD;
        conn: Sys->Connection;
        tchan: chan of (array of byte, int, int);
        rchan: chan of array of byte;

        serverlastseenalive: int;

        # public API
        dhtfindnode: fn(nil: self ref Local, id: Key, nodes: array of ref Node): ref Node;
        dhtfindvalue: fn(nil: self ref Local, id: Key): list of ref StoreItem;
        dhtstore: fn(nil: self ref Local, key: Key, data: array of byte);
        # returns the rtt, or -1 if node is not reachable
        # raises exception if node is not found (??)
        dhtping: fn(nil: self ref Local, id: Key): int;
        # sets the file descriptor for logs, if nil logging is turned off
        setlogfd: fn(nil: self ref Local, fd: ref Sys->FD);

        # do some periodic processing
        process: fn(nil: self ref Local);
        # find k closest nodes to the given one
        findkclosest: fn(nil: self ref Local, id: Key): array of ref Node;
        # process some message
        processrmsg: fn(nil: self ref Local, buf: array of byte);
        processtmsg: fn(nil: self ref Local, buf: array of byte, raddr: string);
        # actually sends a message to the specified address
        sendmsg: fn(nil: self ref Local, addr: string, data: array of byte, retransmits: int);
        # send the message and setup callback with given channel
        sendtmsg: fn(nil: self ref Local, n: ref Node, msg: ref Tmsg, retransmits: int): chan of ref Rmsg;
        # same as above, but without callbacks
        sendrmsg: fn(nil: self ref Local, prvaddr: string, pubaddr: string, msg: ref Rmsg);
        # log some data
        logevent: fn(nil: self ref Local, source: string, msg: string);
        # fire the event with some interval
        timer: fn(nil: self ref Local);
        # the things that would sync everything
        callbacksproc: fn(nil: self ref Local);
        contactsproc: fn(nil: self ref Local);
        storeproc: fn(nil: self ref Local);
        # finish all internal threads and close the server
        destroy: fn(nil: self ref Local);
        # NAT traversing related methods
        processrandezvousquery: fn(nil: self ref Local, m: ref Tmsg.AskRandezvous, askingnode: ref Node);
        askrandezvous: fn(nil: self ref Local, nodeaddr, srvaddr: string, nodeid, srvid: Key): int;
        queryforrmsg: fn(nil: self ref Local, node: ref Node, msg: ref Tmsg, retransmits: int, callroutine: string): (int, ref Rmsg);
        changeserver: fn(nil: self ref Local);
    };

    init:   fn();
    start:  fn(localaddr: string, bootstrap: array of ref Node, id: Key, logfd: ref Sys->FD): ref Local;

};
