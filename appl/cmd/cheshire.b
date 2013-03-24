implement Cheshire;
include "sys.m";
    sys: Sys;
include "draw.m";
include "sh.m";
include "ip.m";
    ip: IP;
    Udphdr, Udp4hdrlen, IPaddr: import ip;
include "styx.m";
    styx: Styx;
    Rmsg, Tmsg: import styx;
include "styxservers.m";
    styxservers: Styxservers;
    Ebadfid, Enotfound, Eopen, Einuse, Eperm: import Styxservers;
    Styxserver, readbytes, Navigator, Fid: import styxservers;
include "keyring.m";
    keyring: Keyring;
include "security.m";
    random: Random;
    auth: Auth;
include "string.m";
    str: String;
include "daytime.m";
    daytime: Daytime;
include "bigkey.m";
    bigkey: Bigkey;
    Key: import bigkey;
include "hashtable.m";
    hashtable: Hashtable;
    HashTable: import hashtable;
include "dht.m";
    dht: Dht;
    Node, Local, StoreItem: import dht;
include "sort.m";
    sort: Sort;

VStyxServer,
VFolder,
Vmax: con 100 + iota;

MAX_FOLDER_ENTRIES: con 10000; # Some "reasonable" value
MESSAGE_SIZE: con 8216;
NOFID: con ~0;

HASHSIZE : con 10000;

# DhtValue adt and serialisation

BIT32SZ: con 4;
pkey(a: array of byte, o: int, k: Key): int
{
    return parray(a, o, k.data);
}
parray(a: array of byte, o: int, sa: array of byte): int
{
    n := len sa;
    p32(a, o, n);
    a[o+BIT32SZ:] = sa;
    return o+BIT32SZ+n;
}
pstring(a: array of byte, o: int, s: string): int
{
    sa := array of byte s;
    return parray(a, o, sa);
}
p32(a: array of byte, o: int, v: int): int
{
    a[o] = byte v;
    a[o+1] = byte (v>>8);
    a[o+2] = byte (v>>16);
    a[o+3] = byte (v>>24);
    return o+BIT32SZ;
}
g32(a: array of byte, o: int): (int, int)
{
    if (o + BIT32SZ > len a)
        raise "fail: g32: malformed packet";
    number := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    return (number, o + BIT32SZ);
}
gstring(a: array of byte, o: int): (string, int)
{
    (str, l) := garray(a, o);
    return (string str, l);
}
garray(a: array of byte, o: int): (array of byte, int)
{
    if(o < 0 || o+BIT32SZ > len a)
        raise "fail: garray: malformed packet";
    l: int;
    (l, o) = g32(a, o);
    e := o+l;
    if(e > len a || l < 0)
        raise "fail: garray: malformed packet";
    return (a[o:e], e);
}
gkey(a: array of byte, o: int): (Key, int)
{
    (data, l) := garray(a, o);
    if (len data != Bigkey->BB)
        raise "fail: gkey: malformed packet";
    return (Key(data), l);
}

# Comparator for Sys->Dir entries
DirComp: adt {
    gt: fn(nil: self ref DirComp, d1, d2: ref Sys->Dir): int;
};
DirComp.gt(dc: self ref DirComp, d1, d2: ref Sys->Dir): int
{
    return d1.name > d2.name;
}

Cheshire: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
};
DhtValue: adt {
    name: string;
    pick {
    StyxServer =>
        nodeid: Key;
        styxservid: Key;
    Folder =>
    #Program =>
    #   disCode: array of byte;
    }

    unpack: fn(a: array of byte): (int, ref DhtValue);
    pack: fn(nil: self ref DhtValue): array of byte;
    packedsize: fn(nil: self ref DhtValue): int;
    text: fn(nil: self ref DhtValue): string;
    mtype: fn(nil: self ref DhtValue): int;
};

vtag2type := array[] of {
tagof DhtValue.StyxServer => VStyxServer,
tagof DhtValue.Folder => VFolder
};
DhtValue.mtype(v: self ref DhtValue): int
{
    return vtag2type[tagof v];
}
DhtValue.packedsize(v: self ref DhtValue): int
{
    size := 1; # one byte reserved for type info
    size += BIT32SZ;
    size += len array of byte v.name;
    pick vv := v {
    StyxServer =>
        size += 2 * (BIT32SZ + Bigkey->BB);
    Folder =>
        # no data
    }
    return size;
}
DhtValue.pack(v: self ref DhtValue): array of byte
{
    o := 0;
    a := array [v.packedsize()] of byte;
    a[o++] = byte v.mtype();
    o = pstring(a, o, v.name);
    pick vv := v {
    StyxServer =>
        o = pkey(a, o, vv.nodeid);
        o = pkey(a, o, vv.styxservid);
    Folder =>
        # no data
    * =>
        raise "fail:DhtValue.pack:bad value type";
    }
    return a;
}
DhtValue.unpack(a: array of byte): (int, ref DhtValue)
{
    o := 1;
    mtype := a[0];
    name: string;
    (name, o) = gstring(a, o);
    case int mtype {
    VStyxServer =>
        nodeid, styxservid: Key;
        (nodeid, o) = gkey(a, o);
        (styxservid, o) = gkey(a, o);
        return (len a, ref DhtValue.StyxServer(name, nodeid, styxservid));
    VFolder =>
        return (len a, ref DhtValue.Folder(name));
    * =>
        raise "fail:DhtValue.unpack:bad value type";
    }
}
DhtValue.text(v: self ref DhtValue): string
{
    if (v == nil)
        return "DhtValue(nil)";
    pick vv := v {
    StyxServer =>
        return sys->sprint("DhtValue.StyxServer(%s, %s, %s)", vv.name, vv.nodeid.text(), vv.styxservid.text());
    Folder =>
        return sys->sprint("DhtValue.Folder(%s)", vv.name);
    * =>
        return "DhtValue.unknown()";
    }
}

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail:bad module";
}

straplist: array of ref Node;

nav: ref Navigator;
user: string;
localaddr: string;
localkey: Key;
authinfo: ref Keyring->Authinfo;

qidtopath: ref Hashtable->HashTable[string];
pathtoqid: ref Hashtable->HashTable[string];

synthdirmap: ref Hashtable->HashTable[list of big];
synthfilemap: ref Hashtable->HashTable[ref Sys->Dir];
synthupmap: ref Hashtable->HashTable[string];

mountpoints: ref Hashtable->HashTable[string];

stderr: ref Sys->FD;
dhtlogfd: ref Sys->FD;
mainpid: int;

Qdummy, Qroot, Qcheshire, Qwelcome, Qaddserver,
Qdhtlog, Qlastpath: con big iota;
Qlast: big;
reservedqids := array [] of 
  {Qroot, Qcheshire, Qwelcome, Qaddserver, Qdhtlog};

local: ref Local;

mountedon: string;

# helper functions

contains(a: array of big, x: big): int
{
    if (a == nil)
        return 0;
    for (i := 0; i < len a; ++i)
        if (a[i] == x)
            return i;
    return 0;
}

# some styx helpers

readfile(m: ref Tmsg.Read, fd: ref Sys->FD): ref Rmsg.Read
{
    r := ref Rmsg.Read(m.tag, nil);
    if (fd == nil)
        return r;
    buf := array [m.count] of byte;
    readbytes := sys->pread(fd, buf, len buf, m.offset);
    if (readbytes == 0)
        return r;
    r.data = buf[:readbytes];
    return r;
}

writebytes(m: ref Tmsg.Write, d: array of byte): ref Rmsg.Write
{
    r := ref Rmsg.Write(m.tag, 0);
    if(m.offset >= big len d || m.offset < big 0)
        return r;
    offset := int m.offset;
    e := offset + len m.data;
    if(e > len d)
        e = len d;
    for (i := offset; i < e; i++)
        d[i] = m.data[i];
    r.count = len m.data;
    return r;
}

writestring(m: ref Tmsg.Write): (ref Rmsg.Write, string)
{
    r := ref Rmsg.Write(m.tag, len m.data);
    return (r, string m.data);
}

# main cheshire implementation

startdht()
{
    dhtlogname := sys->sprint("/tmp/%ddhtlog.log", mainpid);
    dhtlogfd = sys->create(dhtlogname, Sys->ORDWR, 8r700);
    local = dht->start(localaddr, straplist, localkey, dhtlogfd);
    if (local == nil)
    {
        sys->fprint(stderr, "Very bad, dht init error: %r\n");
        raise sys->sprint("fail:dht:%r");
    }
    if (dhtlogfd != nil)
        sys->fprint(stderr, "Dht logging started\n");
    sys->fprint(stderr, "Dht started\n");
    local.usermsghandler = chan of (ref Dht->Tmsg.User);
    spawn dhtmsghandler();
}

init(nil: ref Draw->Context, args: list of string)
{
    # TODO: fix arguments processing, usage, help and mounting
    args = tl args;
    if (len args != 2)
        raise "fail:usage: cheshire <local addr> <neighbours file>";
    # loading modules
    sys = load Sys Sys->PATH;
    
    styx = load Styx Styx->PATH;
    if (styx == nil)
        badmodule(Styx->PATH);
    styx->init();
    
    styxservers = load Styxservers Styxservers->PATH;
    if (styxservers == nil)
        badmodule(Styxservers->PATH);
    styxservers->init(styx);
    styxservers->traceset(1);
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
        badmodule(Daytime->PATH);
    random = load Random Random->PATH;
    if (random == nil)
        badmodule(Random->PATH);
    auth = load Auth Auth->PATH;
    if (auth == nil)
        badmodule(Auth->PATH);
    if ((err := auth->init()) != nil)
        badmodule("auth init fail: " + err);
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
        badmodule(Keyring->PATH);
    str = load String String->PATH;
    if (str == nil)
        badmodule(String->PATH);
    dht = load Dht Dht->PATH;
    if (dht == nil)
        badmodule(Dht->PATH);
    dht->init();
    bigkey = load Bigkey Bigkey->PATH;
    if (bigkey == nil)
        badmodule(Bigkey->PATH);
    bigkey->init();
    sort = load Sort Sort->PATH;
    if (sort == nil)
        badmodule(Sort->PATH);
    hashtable = load Hashtable Hashtable->PATH;
    if (hashtable == nil)
        badmodule(Hashtable->PATH);

    localkey = Key.generate();
    localaddr = hd args;
    # find out the current user to make it the owner of all folders
    user = getcuruser();
    stderr = sys->fildes(2);
    mainpid = sys->pctl(0, nil);
    mountedon = "/wonderland";

    # setup authinfo for authorizing external servers
    authinfo = keyring->readauthinfo("/usr/" + user + "/keyring/default");
    if (authinfo == nil)
        sys->fprint(stderr, "Reading default keyring failed, no server mounts will be performed\n");

    # creating navigators and servers
    sys->fprint(stderr, "Creating styxservers\n");
    navops := chan of ref Styxservers->Navop;
    (tchan, srv) := Styxserver.new(sys->fildes(0), Navigator.new(navops), Qroot);
    spawn navigator(navops);

    # creating file tree
    # TODO: fix permissions
    synthdirmap = hashtable->new(HASHSIZE, big 0 :: nil);
    synthdirmap.insert(string Qroot, Qcheshire :: nil);
    synthdirmap.insert(string Qcheshire, Qwelcome :: Qaddserver :: Qdhtlog :: nil);
    synthfilemap = hashtable->new(HASHSIZE, ref dir(".", Sys->DMDIR | 8r555, Qroot));
    synthfilemap.insert(string Qroot, ref dir(".", Sys->DMDIR | 8r555, Qroot));
    synthfilemap.insert(string Qcheshire, ref dir("cheshire", Sys->DMDIR | 8r555, Qcheshire));
    synthfilemap.insert(string Qwelcome, ref dir("welcome", 8r555, Qwelcome));
    synthfilemap.insert(string Qaddserver, ref dir("addserver", 8r777, Qaddserver));
    synthfilemap.insert(string Qdhtlog, ref dir("dhtlog", 8r555, Qdhtlog));
    synthupmap = hashtable->new(HASHSIZE, "");
    synthupmap.insert(string Qcheshire, string Qroot);

    # parse bootstrap file
    fd := sys->open(hd tl args, Sys->OREAD);
    if (fd == nil)
        raise "fail:bootstrap file not found";
    buf := array [8192] of byte;
    readbytes := sys->read(fd, buf, len buf);
    if (readbytes < 0)
        raise "fail:bootstrap file not found";
    sys->fprint(stderr, "Parsing bootstrap\n");
    straplist = strapparse(string buf[:readbytes]);
    startdht();

    Qlast = Qlastpath;

    sys->fprint(stderr, "Cheshire is up and running!\n");
    qidtopath = hashtable->new(HASHSIZE, "");
    pathtoqid = hashtable->new(HASHSIZE, "");
    qidtopath.insert(string Qroot, "/");
    pathtoqid.insert("/", string Qroot);

    mountpoints = hashtable->new(HASHSIZE, "");
    runningstyxservers = hashtable->new(HASHSIZE, stderr);
    styxclients = hashtable->new(HASHSIZE, stderr);

    # starting message processing loop
    for (;;) {
        gm := <-tchan;
        if (gm == nil) {
            sys->fprint(stderr, "Walking away...\n");
            local.destroy();
            navops <-= nil;
            exit;
        }
        r := handlemsg(gm, srv, nav);
        if (r != nil)
            srv.reply(r);
    }
}

# Main cheshire message handling loop

handlemsg(gm: ref Styx->Tmsg, srv: ref Styxserver, nav: ref Navigator): ref Styx->Rmsg
{
    reply: ref Styx->Rmsg;
    reply = nil;
    pick m := gm {
    Readerror =>
        sys->fprint(stderr, "Some read error: %s\n", m.error);
        return ref Rmsg.Error(m.tag, "Some read error");
    Read =>
        (c, err) := srv.canread(m);
        if(c == nil)
            return ref Rmsg.Error(m.tag, err);
        if((c.qtype & Sys->QTDIR) == 0) # then reading files
        {
            answer: ref Rmsg;
            if (c.data != nil && len c.data > 0)
                answer = styxservers->readbytes(m, c.data);
            else if (c.path == Qwelcome)
                answer = styxservers->readstr(m, "Hello, and welcome to the Wonderland!\n");
            else if (c.path == Qaddserver)
                answer = styxservers->readstr(m, "Write something like <serveraddr> <serverpath>\n");
            else if (c.path == Qdhtlog)
                answer = readfile(m, dhtlogfd);
            else
                answer = ref Rmsg.Error(m.tag, Enotfound);
            return answer;
        }
        else
            srv.read(m);
    Write =>
        (c, err) := srv.canwrite(m);
        if(c == nil)
            return ref Rmsg.Error(m.tag, err);
        if((c.qtype & Sys->QTDIR) == 0) # then writing files
        {
            answer: ref Rmsg;
            if (c.path == Qaddserver)
            {
                request: string;
                (answer, request) = writestring(m);
                result := serverparse(request);
                c.data = array of byte result;
            }
            else
                answer = ref Rmsg.Error(m.tag, Eperm);
            return answer;
        }
    Remove =>
        # TODO: Unmap from fidmap and mounpoints, close connection
        srv.default(gm);
    * =>
        srv.default(gm);
    }
    return reply;
}

# Navigator implementation, for cheshire to know the content of the folders

navigator(navops: chan of ref styxservers->Navop)
{
    while((m := <-navops) != nil){

        # first check our own synthetic fs
        synthres := synthnavigator(m);
        if (synthres == 1)
            continue;

        # then handle the wonderland data
        pick n := m {
        Stat =>
            path := qidtopath.find(string n.path);
            (nil, name) := str->splitr(path, "/");
            n.reply <-= (ref dir(name, Sys->DMDIR | 8r555, n.path), nil);
        Walk =>
            found := 0;
            cwd := qidtopath.find(string n.path);
            # try to go up
            if (n.name == ".." && n.path != Qroot)
            {
                # strip last /
                curdir := cwd[:len cwd - 1];
                # split the path in two parts
                (uppath, upname) := str->splitr(curdir, "/");
                n.reply <-= (ref dir(upname, Sys->DMDIR | 8r555, big pathtoqid.find(uppath)), nil);
                break;
            }

            destpath := cwd + n.name + "/";
            destqid := pathtoqid.find(destpath);
            if (destqid == nil)
            {
                destqid = string ++Qlast;
                pathtoqid.insert(destpath, destqid);
                qidtopath.insert(destqid, destpath);
            }

            keydata := array [keyring->SHA1dlen] of byte;
            hashdata := array of byte qidtopath.find(string n.path);
            keyring->sha1(hashdata, len hashdata, keydata, nil);
            content := local.dhtfindvalue(Key(keydata[:Bigkey->BB]));
            for (l := content; l != nil && !found; l = tl l)
            {
                (nil, I) := DhtValue.unpack((hd l).data);
                if (I.name == n.name)
                {
                    found = 1;
                    pick entry := I
                    {
                        StyxServer =>
                            if (mountpoints.find(destpath) == nil)
                            {
                                mountpoints.insert(destpath, "started");
                                spawn mountserver(entry, mountedon + destpath);
                            }
                            n.reply <-= (ref dir(n.name, Sys->DMDIR | 8r555, big destqid), nil);
                        Folder =>
                            qidtopath.insert(destqid, destpath);
                            pathtoqid.insert(destpath, destqid);
                            n.reply <-= (ref dir(n.name, Sys->DMDIR | 8r555, big destqid), nil);
                    }
                }
            }
            if (!found)
                n.reply <-= (nil, "fail: path not found");
        Readdir =>
            cwd := qidtopath.find(string n.path);
            keydata := array [keyring->SHA1dlen] of byte;
            hashdata := array of byte cwd;
            keyring->sha1(hashdata, len hashdata, keydata, nil);
            content := local.dhtfindvalue(Key(keydata[:Bigkey->BB]));
            for (l := content; l != nil; l = tl l)
            {
                n.offset--;
                if (n.offset >= 0)
                    continue;

                (nil, I) := DhtValue.unpack((hd l).data);
                entryqid := pathtoqid.find(cwd + I.name + "/");
                if (entryqid == nil)
                {
                    entryqid = string ++Qlast;
                    pathtoqid.insert(cwd + I.name + "/", entryqid);
                    qidtopath.insert(entryqid, cwd + I.name + "/");
                }
                entry := dir(I.name, 8r555 | Sys->DMDIR, big entryqid); 
                n.reply <-= (ref entry, nil);

                n.count--;
                if (n.count == 0)
                    break;
            }
            n.reply <-= (nil, nil);
        }
    }
}

# Our own, synthetic fs handling (/cheshire/)

synthnavigator(op: ref styxservers->Navop): int
# returns 1 if we should finish navop processing
{
    pick n := op {
        Stat =>
            file := synthfilemap.find(string n.path);
            if (file != nil)
            {
                n.reply <-= (file, nil);
                return 1;
            }
        Walk =>
            if (n.name == "..")
            {
                updirqid := synthupmap.find(string n.path);
                updir := synthfilemap.find(string updirqid);
                if (updir != nil)
                {
                    n.reply <-= (updir, nil);
                    return 1;
                }
            }
            children := synthdirmap.find(string n.path);
            for (it := children; it != nil; it = tl it)
            {
                file := synthfilemap.find(string hd it);
                if (file != nil && file.name == n.name)
                {
                    n.reply <-= (file, nil);
                    return 1;
                }
            }
        Readdir =>
            children := synthdirmap.find(string n.path);
            for (it := children; it != nil; it = tl it)
            {
                n.offset--;
                if (n.offset >= 0)
                    continue;
                n.reply <-= (synthfilemap.find(string hd it), nil);
                n.count--;
                if (n.count == 0)
                    break;
            }
    }
    return 0;
}

# Cheshire styx server handling, common functions

styxclients: ref Hashtable->HashTable[ref Sys->FD];     # key - node addr

dhtmsghandler()
{
    while (1)
    {
        msg := <-local.usermsghandler;
        sys->fprint(stderr, "Incoming msg from %s", (ref msg.sender).text());
        # strip the destination from the message
        if (len msg.data <= Bigkey->BB)
        {
            sys->fprint(stderr, "Message too short, ignored\n");
            continue;
        }
        styxservid := Key(msg.data[:Bigkey->BB]);
        msgdata := msg.data[Bigkey->BB:];
        # firstly clone the server for the client, if it's his first message
        # TODO: why pubaddr? we deserve better address
        clientfd := styxclients.find(msg.sender.pubaddr);
        if (clientfd == nil)
        {
            styxservfd := runningstyxservers.find(styxservid.text());
            if (styxservfd == nil)
            {
                sys->fprint(stderr, "The running styx server with id %s does not exist\n", styxservid.text());
                continue;
            }
            sys->fprint(stderr, "Cloning server for this client\n");
            clientfd = cloneserver(styxservfd);
            styxclients.insert(msg.sender.pubaddr, clientfd);
        }
        # if ok, pass the data to styxserver and push answer to the node
        sys->fprint(stderr, "Passing packet to styxserver\n");
        buf := array [Styx->MAXRPC] of byte;
        # don't forget to strip server id
        sys->write(clientfd, msgdata, len msgdata);
        readbytes := sys->read(clientfd, buf, len buf);
        local.sendrmsg(msg.sender.prvaddr, msg.sender.pubaddr,
            ref (Dht->Rmsg).User(msg.uid, local.node.id, msg.sender.id, buf[:readbytes]));
        sys->fprint(stderr, "Answered\n");
    }
}

# Cheshire styx server handling, mounting side

mountserver(serv: ref DhtValue.StyxServer, path: string)
{
    servnode := local.dhtfindnode(serv.nodeid, nil);
    if (serv.nodeid.eq(local.node.id))
        servnode = ref local.node;
    if (servnode == nil)
    {
        sys->fprint(stderr, "Node hosting server not found, try again later\n");
        return;
    }
    # we will use that to proxy styx requests
    fds := array [2] of ref Sys->FD;
    sys->pipe(fds);
    spawn remotemounter(servnode, serv.styxservid, fds[1]);
    sys->fprint(stderr, "Waiting for sys->mount to return\n");
    sys->mount(fds[0], nil, path, Sys->MREPL, nil);
    sys->fprint(stderr, "Mount success, maybe\n");
}

remotemounter(servnode: ref Node, styxservid: Key, servfd: ref Sys->FD)
{
    sys->fprint(stderr, "Starting mounter, using node: %s\n", servnode.text());
    while (1)
    {
        # pass the message to styx server through dht
        buf := array [Styx->MAXRPC] of byte;
        sys->fprint(stderr, "Reading data from sys->mount\n");
        readbytes := sys->read(servfd, buf, len buf);
        sys->fprint(stderr, "Got something - %d bytes, processing\n", readbytes);
        (l, m) := Tmsg.unpack(buf[:readbytes]);
        sys->fprint(stderr, "Trying to unpack: %d\n", l);
        if (m != nil)
            sys->fprint(stderr, "Message: %s\n", m.text());
        # prepare the message
        msg := array [readbytes + Bigkey->BB] of byte;
        msg[:] = styxservid.data[:Bigkey->BB];
        msg[Bigkey->BB:] = buf[:readbytes];
        # send it using dht power
        dhtmsg := ref (Dht->Tmsg).User(Key.generate(), local.node, servnode.id, msg);
        sys->fprint(stderr, "Message sent to server: %s\n", styxservid.text());
        sys->fprint(stderr, "Awaiting response\n");
        (rtt, reply) := local.queryforrmsg(servnode, dhtmsg, "cheshire:remotemounter");
        if (reply != nil)
            pick r := reply {
                User =>
                    sys->fprint(stderr, "Got answer (%d bytes), passing back to system\n", len r.data);
                    {
                        (l, m) := Rmsg.unpack(r.data);
                        sys->fprint(stderr, "Trying to unpack the answer: %d\n", l);
                        if (m != nil)
                            sys->fprint(stderr, "Message: %s\n", m.text());
                    }
                    sys->write(servfd, r.data, len r.data);
            }
        else
        {
            answer := ref Rmsg->Error(m.tag, "Dht traverse error: message wait timeout");
            packedanswer := answer.pack();
            sys->write(servfd, packedanswer, len packedanswer);
        }
    }
}

# Cheshire styx server handling, server side

runningstyxservers: ref Hashtable->HashTable[ref Sys->FD]; # key - styxservid

serverparse(s: string): string
{
    (nil, strings) := sys->tokenize(s, "\n");
    for (it := strings; it != nil; it = tl it)
    {
        sys->fprint(stderr, "Parsing addserver entry: %s\n", hd it);
        (cmd, fullpath) := str->splitr(hd it, " ");
        if (fullpath == nil || cmd == nil || cmd[:1] == "#")
            continue;
        #fullpath = fullpath[1:]; # skip one space
        (path, name) := str->splitr(fullpath, "/");
        if (path == nil)
            path = "/";

        # add the given server to dht, key=hash(fullpath)
        value := ref DhtValue.StyxServer(name, local.node.id, Key.generate());
        keydata := array [keyring->SHA1dlen] of byte;
        hashdata := array of byte path;
        keyring->sha1(hashdata, len hashdata, keydata, nil);
        local.dhtstore(Key(keydata[:Bigkey->BB]), value.pack());
        sys->fprint(stderr, "Added server by path: %s, dht key: %s\n%s\n", 
                            path, Key(keydata[:Bigkey->BB]).text(), value.text());
        # the most importand part:
        startserver(cmd, value.styxservid);
        # and now for every path component
        (nil, folders) := sys->tokenize(path, "/");
        curpath := "/";
        while (folders != nil)
        {
            folder := hd folders;
            folders = tl folders;

            keydata := array [keyring->SHA1dlen] of byte;
            value := ref DhtValue.Folder(folder);
            hashdata = array of byte curpath;
            keyring->sha1(hashdata, len hashdata, keydata, nil);
            local.dhtstore(Key(keydata[:Bigkey->BB]), value.pack());
            sys->fprint(stderr, "Added folder by path: %s, dht key: %s\n%s\n",
                                curpath, Key(keydata[:Bigkey->BB]).text(), value.text());

            curpath += folder + "/";
        }
    }
    return "ok"; 
}

startserver(cmd: string, id: Key)
{
    sys->fprint(stderr, "Starting styx server with cmd: %s and key %s\n", cmd, id.text());
    # TODO: here, above and below: despawn everything carefully, watch
    #       closed streams and think about isolating threads (more or less)
    ch := chan of int;
    (nil, args) := sys->tokenize(cmd, " ");
    runningstyxservers.insert(id.text(), popen(nil, args, ch));
}

cloneserver(servfd: ref Sys->FD): ref Sys->FD
{
    ch := chan of ref Sys->FD;
    sys->fprint(stderr, "Spawning exportproc\n");
    spawn exportproc(ch, servfd);
    return <-ch;
}

exportproc(ch: chan of ref Sys->FD, servfd: ref Sys->FD)
{
    fds := array [2] of ref Sys->FD;
    sys->pipe(fds);
    sys->fprint(stderr, "Debug 1\n");
    ch <-= fds[1]; # return the second pipe end
    sys->fprint(stderr, "Debug 2\n");
    # isolate self
    sys->pctl(Sys->NEWFD | Sys->NEWNS, 2 :: servfd.fd :: fds[0].fd :: nil);
    servfd = sys->fildes(servfd.fd);
    fds[0] = sys->fildes(fds[0].fd);
    stderr := sys->fildes(2);

    # comment from styxlisten.b:
    # XXX unfortunately we cannot pass through the aname from
    # the original attach, an inherent shortcoming of this scheme.
    sys->fprint(stderr, "Mounting on /\n");
    if (sys->mount(servfd, nil, "/", Sys->MREPL|Sys->MCREATE, nil) == -1)
        sys->fprint(stderr, "Cannot mount: %r\n");

    sys->fprint(stderr, "Exporting /\n");
    sys->export(fds[0], "/", Sys->EXPASYNC);
}

popen(ctxt: ref Draw->Context, argv: list of string, lsync: chan of int): ref Sys->FD
{
    sync := chan of int;
    fds := array [2] of ref Sys->FD;
    sys->pipe(fds);
    spawn runcmd(ctxt, argv, fds[0], sync, lsync);
    #<-sync;
    return fds[1];
}

runcmd(ctxt: ref Draw->Context, argv: list of string, stdin: ref Sys->FD,
        sync: chan of int, lsync: chan of int)
{
    sys->pctl(Sys->FORKFD, nil);
    sys->dup(stdin.fd, 0);
    stdin = nil;
    #sync <-= 0;
    sh := load Sh Sh->PATH;
    sys->fprint(stderr, "Executing %s\n", hd argv);
    e := sh->run(ctxt, argv);
    #kill(<-lsync, "kill");

    if(e != nil)
        sys->fprint(stderr, "cheshire: command exited with error: %s\n", e);
    else
        sys->fprint(stderr, "cheshire: command exited\n");

}

kill(pid: int, how: string)
{
    sys->fprint(sys->open("/prog/"+string pid+"/ctl", Sys->OWRITE), "%s", how);
}

# Misc utility functions

strapparse(s: string): array of ref Node
{
    (nil, strings) := sys->tokenize(s, "\n");
    ret := array [len strings] of ref Node;
    i := 0;
    for (it := strings; it != nil; it = tl it)
    {
        # TODO: adopt to the new Node format
        sys->fprint(stderr, "Parsing bootstrap entry: %s\n", hd it);
        (nil, blocks) := sys->tokenize(hd it, " ");
        if (blocks == nil || len blocks != 2 || (hd blocks)[:1] == "#")
            continue;
        ret[i++] = ref Node(*Key.parse(hd blocks), hd tl blocks, hd tl blocks, 
                                                   hd tl blocks, *Key.parse(hd blocks));
    }
    return ret[:i];
}

getcuruser(): string
{
    fd := sys->open("/dev/user", Sys->OREAD);
    if (fd == nil)
        return "";
    buf := array [8192] of byte;
    readbytes := sys->read(fd, buf, len buf);
    if (readbytes <= 0)
        return "";
    return string buf[:readbytes];
}

Blankdir: Sys->Dir;
dir(name: string, perm: int, qid: big): Sys->Dir
{
    d := Blankdir;
    d.name = name;
    d.uid = user;
    d.gid = "me";
    d.qid.path = qid;
    if (perm & Sys->DMDIR)
        d.qid.qtype = Sys->QTDIR;
    else
        d.qid.qtype = Sys->QTFILE;
    d.mode = perm;
    return d;
}
