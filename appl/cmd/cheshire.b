implement Cheshire;
include "sys.m";
    sys: Sys;
include "draw.m";
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

    nametree: Nametree;
    Tree: import nametree;

VStyxServer,
VFolder,
Vmax: con 100 + iota;

MAX_ENTRIES: con 10000; # Some "reasonable" value
MESSAGE_SIZE: con 8216;
NOFID: con ~0;

HASHSIZE : con 10000;

# DhtValue adt and serialisation

BIT32SZ: con 4;
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
    pick {
    StyxServer =>
        name: string;
        addr: string;
    Folder =>
        name: string;
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
    pick vv := v {
    StyxServer =>
        size += BIT32SZ;
        size += len array of byte vv.name;
        size += BIT32SZ;
        size += len array of byte vv.addr;
    Folder =>
        size += BIT32SZ;
        size += len array of byte vv.name;
    }
    return size;
}
DhtValue.pack(v: self ref DhtValue): array of byte
{
    o := 0;
    a := array [v.packedsize()] of byte;
    a[o++] = byte v.mtype();
    pick vv := v {
    StyxServer =>
        o = pstring(a, o, vv.name);
        o = pstring(a, o, vv.addr);
    Folder =>
        o = pstring(a, o, vv.name);
    * =>
        raise "fail:DhtValue.pack:bad value type";
    }
    return a;
}
DhtValue.unpack(a: array of byte): (int, ref DhtValue)
{
    o := 1;
    mtype := a[0];
    case int mtype {
    VStyxServer =>
        name, addr: string;
        (name, o) = gstring(a, o);
        (addr, o) = gstring(a, o);
        return (len a, ref DhtValue.StyxServer(name, addr));
    VFolder =>
        name: string;
        (name, o) = gstring(a, o);
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
        return sys->sprint("DhtValue.StyxServer(%s, %s)", vv.name, vv.addr);
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

tree: ref Tree;
nav: ref Navigator;
user: string;
localaddr: string;
localkey: Key;

MountPoint: adt
{
    addr: string;
    cfd, dfd: ref Sys->FD;
    rootfid: int;
    parentfid: int;
};

fidmap: ref Hashtable->HashTable[ref MountPoint];
mountpoints: ref Hashtable->HashTable[string];

stderr: ref Sys->FD;
dhtlogfd: ref Sys->FD;
mainpid: int;

Qdummy, Qroot, Qcheshire, Qwelcome, Qaddserver, Qbootstrap,
Qdhtlog, Qlastpath: con big iota;
Qlast: big;
reservedqids := array [] of 
  {Qroot, Qcheshire, Qwelcome, Qaddserver, Qbootstrap, Qdhtlog};

local: ref Local;

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
}

init(nil: ref Draw->Context, args: list of string)
{
    args = tl args;
    if (len args == 0)
        raise "fail:local address required as first argument";
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
    nametree = load Nametree Nametree->PATH;
    if (nametree == nil)
        badmodule(Nametree->PATH);
    nametree->init();
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
        badmodule(Daytime->PATH);
    random = load Random Random->PATH;
    if (random == nil)
        badmodule(Random->PATH);
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

    # creating navigators and servers
    sys->fprint(stderr, "Creating styxservers\n");
    navops: chan of ref Styxservers->Navop;
    (tree, navops) = nametree->start();
    nav = Navigator.new(navops);
    (tchan, srv) := Styxserver.new(sys->fildes(0), nav, Qroot);

    # creating file tree
    # TODO: fix permissions
    sys->fprint(stderr, "Setting up nametree\n");
    tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
    tree.create(Qroot, dir("cheshire", Sys->DMDIR | 8r555, Qcheshire));
    tree.create(Qcheshire, dir("welcome", 8r555, Qwelcome));
    tree.create(Qcheshire, dir("addserver", 8r777, Qaddserver));
    tree.create(Qcheshire, dir("dhtlog", 8r555, Qdhtlog));
    if (len args == 1)
        tree.create(Qcheshire, dir("bootstrap", 8r755, Qbootstrap));
    else
    {
        fd := sys->open(hd tl args, Sys->OREAD);
        if (fd == nil)
            raise "fail:bootstrap file not found";
        buf := array [8192] of byte;
        readbytes := sys->read(fd, buf, len buf);
        if (readbytes <= 0)
            raise "fail:bootstrap file not found";
        sys->fprint(stderr, "Parsing bootstrap\n");
        straplist = strapparse(string buf[:readbytes]);
        startdht();
    }
    Qlast = Qlastpath;

    sys->fprint(stderr, "Cheshire is up and running!\n");
    mountpoints = hashtable->new(HASHSIZE, "Dummy string value");
    fidmap = hashtable->new(HASHSIZE, ref MountPoint("", stderr, stderr, 0, 0));

    # starting message processing loop
    for (;;) {
        gm := <-tchan;
        sys->fprint(stderr, "Handlemsg: %s\n", gm.text());
        if (gm == nil) {
            sys->fprint(stderr, "Walking away...\n");
            tree.quit();
            if (local != nil)
                local.destroy();
            exit;
        }
        e := handlemsg(gm, srv, tree, nav);
        if (e != nil)
            srv.reply(ref Rmsg.Error(gm.tag, e));
    }
}

handlemsg(gm: ref Styx->Tmsg, srv: ref Styxserver, tree: ref Tree, nav: ref Navigator): string
{
    pick m := gm {
    # some processing will be here some day...
    # now just let the server handle everything
    Readerror =>
        sys->fprint(stderr, "Some read error: %s\n", m.error);
    Read =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
        {
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm)); 
            break;
        }
        (c, err) := srv.canread(m);
        if(c == nil)
            return err;
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
            srv.reply(answer);
        }
        else
            srv.read(m);
    Write =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
        {
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
            break;
        }
        (c, err) := srv.canwrite(m);
        if(c == nil)
            return err;
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
            else if (c.path == Qbootstrap && straplist == nil)
            {
                request: string;
                (answer, request) = writestring(m);
                straplist = strapparse(request);
                startdht();
            }
            else
                answer = ref Rmsg.Error(m.tag, Eperm);
            srv.reply(answer);
        }
    Walk =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
        # Not our domain - passing
        {
            if (m.fid == mnt.rootfid && m.names != nil && m.names[0] == "..")
            {
                pFid := srv.getfid(mnt.parentfid);
                srv.reply(ref Rmsg.Walk(m.tag, array [] of {Sys->Qid(pFid.path, pFid.qtype, 0)})); # TODO: fix version
            }
            else
            {
                fidmap.insert(string m.newfid, mnt);
                srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm)); # Pass message
            }
            break;
        }

        # Get updated contents from DHT
        cursrvpath := srv.getfid(m.fid).path;
        cwd := tree.getpath(cursrvpath);
        cwd = cwd + "/";
        cwd = cwd[1:len cwd];
        sys->fprint(stderr, "CWD: %s\n", cwd);
        keydata := array [keyring->SHA1dlen] of byte;
        hashdata := array of byte cwd;
        keyring->sha1(hashdata, len hashdata, keydata, nil);
        dirkey := Key(keydata[:Bigkey->BB]);

        newitems := local.dhtfindvalue(dirkey);

        newcontent := array [len newitems] of ref Sys->Dir;
        last := 0;
        for (l := newitems; l != nil; l = tl l)
        {
            entry: Sys->Dir;
            (nil, I) := DhtValue.unpack((hd l).data);
            pick item := I 
            {
                StyxServer =>
                     entry = dir(item.name, 8r555, Qdummy); 
                     mountpoints.insert(cwd + "/" + item.name, item.addr);
                Folder =>
                     entry = dir(item.name, Sys->DMDIR | 8r555, Qdummy); 
                * =>
                    raise "fail:unknown DhtValue type";
            }
            newcontent[last++] = ref entry;
        }

        # Get current contents from navigator
        curcontent := nav.readdir(cursrvpath, 0, MAX_ENTRIES); 
        
        # Update the nametree according to new content
        sort->sort(ref DirComp(), curcontent);
        sort->sort(ref DirComp(), newcontent);
        # Debug
        sys->fprint(stderr, "Current directory content:\n");
        for (i := 0; i < len curcontent; ++i)
            sys->fprint(stderr, "  ./%s\n", curcontent[i].name);
        sys->fprint(stderr, "New directory content:\n");
        for (i = 0; i < len newcontent; ++i)
            sys->fprint(stderr, "  ./%s\n", newcontent[i].name);
        (curptr, newptr) := (0, 0);
        while (curptr < len curcontent && newptr < len newcontent)
        {
            while (curptr < len curcontent &&
                   newptr < len newcontent &&
                   newcontent[newptr].name < curcontent[curptr].name)
            {
                # Add, move newptr
                newcontent[newptr].qid.path = ++Qlast;
                tree.create(cursrvpath, *newcontent[newptr]);
                ++newptr;
            }
            while (curptr < len curcontent &&
                   newptr < len newcontent &&
                   newcontent[newptr].name == curcontent[curptr].name)
            {
                # Skip, move both
                ++newptr;
                ++curptr;
            }
            while (curptr < len curcontent &&
                   newptr < len newcontent &&
                   newcontent[newptr].name > curcontent[curptr].name)
            {
                # Delete, move curptr
                # TODO: remove from fidmap, mounpoints, 
                # TODO: recursive clear for dirs, recursive unmap for servers
                if (!contains(reservedqids, curcontent[curptr].qid.path))
                    tree.remove(curcontent[curptr].qid.path);
                ++curptr;
            }
        }
        while (newptr < len newcontent)
        {
            # Add
            newcontent[newptr].qid.path = ++Qlast;
            tree.create(cursrvpath, *newcontent[newptr]);
            ++newptr;
        }
        while (curptr < len curcontent)
        {
            # Delete
            if (!contains(reservedqids, curcontent[curptr].qid.path))
                tree.remove(curcontent[curptr].qid.path);
            ++curptr;
        }

        upcontent := nav.readdir(cursrvpath, 0, MAX_ENTRIES); 
        sort->sort(ref DirComp(), upcontent);
        sys->fprint(stderr, "Updated directory content:\n");
        for (i = 0; i < len upcontent; ++i)
            sys->fprint(stderr, "  ./%s\n", upcontent[i].name);

        # Mount in case we cd to styxserver
        # Connect, Map, Version, TODO: Auth /TODO, Attach.
        if (m.names != nil && 
           (addr := mountpoints.find(cwd + "/" + m.names[0])) != nil)
        {
            sys->fprint(stderr, "Dialing to %s -- ", addr);
            (err, conn) := sys->dial(addr, "");
            if (err != 0)
            {
                sys->fprint(stderr, "Fail: can not connect to styxserver at %s.\n", 
                                     addr);
                break; # Will be cleared by dht, no need to interrupt
            }
            sys->fprint(stderr, "Ok!\n");
            sys->fprint(stderr, "Inserting %s -> %s into fidmap -- ", string m.newfid, addr);
            fidmap.insert(string m.newfid, ref MountPoint(addr, conn.cfd, 
                                                          conn.dfd, m.newfid, m.fid));
            sys->fprint(stderr, "Ok!\n");
            # Attach
            transmitTmsg(conn.cfd, conn.dfd, ref Tmsg.Version(65535, MESSAGE_SIZE, "9P2000"));
            rootqid : ref Sys->Qid;
            pick M := transmitTmsg(conn.cfd, conn.dfd, ref Tmsg.Attach(3, m.newfid, NOFID, user, ""))
            {
                Attach =>
                    rootqid = ref M.qid;
                * => 
                    rootqid = nil;
            }
            if (rootqid == nil)
            {
                sys->fprint(stderr, "Fail: Unable to Attach to server at %s\n", addr);
                srv.reply(ref Rmsg.Error(m.tag, "Fail: Unable to Attach to server"));
            }
            else
                srv.reply(ref Rmsg.Walk(m.tag, array [] of {*rootqid}));
        }
        else
            fid := srv.walk(m);
    Clunk =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
        {
            fidmap.delete(string m.fid);
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm)); # Pass clunk message
        }
        else
            srv.default(gm);
    Open =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
        else
            srv.default(gm);
    Create =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
        else
            srv.default(gm);
    Stat =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
        else
            srv.default(gm);
    Remove =>
        # TODO: Unmap from fidmap and mounpoints, close connection
        if ((mnt := fidmap.find(string m.fid)) != nil)
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
        else
            srv.default(gm);
    Wstat =>
        if ((mnt := fidmap.find(string m.fid)) != nil)
            srv.reply(transmitTmsg(mnt.cfd, mnt.dfd, gm));
        else
            srv.default(gm);
    * =>
        srv.default(gm);
    }
    return nil;
}

transmitTmsg(cfd, dfd: ref Sys->FD, m: ref Styx->Tmsg): ref Styx->Rmsg
{
    sys->fprint(stderr, "Sending %s to server -- ", m.text());
    if (sys->write(dfd, m.pack(), m.packedsize()) != m.packedsize())
    {
        sys->fprint(stderr, "Error writing to data FD.\n");
        return nil;
    }
    sys->fprint(stderr, "Ok\n");
    reply := Rmsg.read(dfd, MESSAGE_SIZE);
    sys->fprint(stderr, "Reply: %s\n", reply.text());
    return reply;
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

serverparse(s: string): string
{
    (nil, strings) := sys->tokenize(s, "\n");
    for (it := strings; it != nil; it = tl it)
    {
        sys->fprint(stderr, "Parsing addserver entry: %s\n", hd it);
        (addr, fullpath) := str->splitl(hd it, " ");
        if (fullpath == nil || addr[:1] == "#")
            continue;
        fullpath = fullpath[1:]; # skip one space
        (path, name) := str->splitr(fullpath, "/");
        if (path == nil)
            path = "/";

        # add the given server to dht, key=hash(fullpath)
        value := ref DhtValue.StyxServer(name, addr);
        keydata := array [keyring->SHA1dlen] of byte;
        hashdata := array of byte path;
        keyring->sha1(hashdata, len hashdata, keydata, nil);
        local.dhtstore(Key(keydata[:Bigkey->BB]), value.pack());
        sys->fprint(stderr, "Added server by path: %s, dht key: %s\n%s\n", 
                            path, Key(keydata[:Bigkey->BB]).text(), value.text());
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

strapparse(s: string): array of ref Node
{
    (nil, strings) := sys->tokenize(s, "\n");
    ret := array [len strings] of ref Node;
    i := 0;
    for (it := strings; it != nil; it = tl it)
    {
        sys->fprint(stderr, "Parsing bootstrap entry: %s\n", hd it);
        (nil, blocks) := sys->tokenize(hd it, " ");
        if (blocks == nil || len blocks != 2 || (hd blocks)[:1] == "#")
            continue;
        ret[i++] = ref Node(*Key.parse(hd blocks), hd tl blocks, 0);
    }
    return ret[:i];
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
