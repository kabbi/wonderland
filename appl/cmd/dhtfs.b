implement Dhtfs;
include "sys.m";
    sys: Sys;
include "draw.m";
include "arg.m";
include "styx.m";
    styx: Styx;
    Rmsg, Tmsg: import styx;
include "styxservers.m";
    styxservers: Styxservers;
    Ebadfid, Enotfound, Eopen, Einuse, Eperm, Eoffset: import Styxservers;
    Styxserver, readbytes, readstr, Navigator, Fid: import styxservers;
    nametree: Nametree;
    Tree: import nametree;
include "daytime.m";
    daytime: Daytime;
include "bigkey.m";
    bigkey: Bigkey;
    Key: import bigkey;
include "hashtable.m";
    hashtable: Hashtable;
    HashTable: import hashtable;
include "keyring.m";
    keyring: Keyring;
include "ip.m";
    ip: IP;
    IPaddr: import ip;
include "dht.m";
    dht: Dht;
    Node, Local, Contacts, StoreItem: import dht;

Dhtfs: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
    initwithdht: fn(local: ref Local, mountpt: string, flags: int, debug: int);
};
Logfile: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
};

HASHSIZE: con 31;
Qroot: con big 16rfffffff;
Qfindnode, Qfindvalue, Qstore, Qping, Qstats, Qstatus, 
Qlocalstore, Qourstore, Qcontacts, Qnode, Qfoundvalues: con big iota + big 16r42;
Qfirstfolder: con big 10000;
Qlastfolder := Qfirstfolder + big 1;
Qlast := Qnode + big 1;
tree: ref Tree;
nav: ref Navigator;
logfilepid: int;
local: ref Local;
findresults: ref HashTable[array of byte];
# if we are started with external local
extlocal: int;

user: string;
stderr: ref Sys->FD;

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail:bad module";
}

usage()
{
    sys->fprint(stderr, "Usage: dhtfs [-a|-b|-ac|-bc] [-D] addr bootstrapfile mountpoint\n");
    raise "fail:usage";
}

msgnames := array [] of {
    "TPing", "RPing",
    "TStore", "RStore",
    "TFindValue", "RFindValue",
    "TFindNode", "RFindNode",
    "TAskRandezvous", "RAskRandezvous",
    "TInvitation", "RInvitation",
    "TObserve", "RObserve",
    "TUser", "RUser"
};

getstats(local: ref Local): string
{
    stats := local.stats;
    ret: string;
    ret += sys->sprint("Startup time: %s\n", daytime->text(daytime->local(stats.startuptime)));
    ret += sys->sprint("Number of sent Tmsgs: %d\n", stats.senttmsgs);
    ret += sys->sprint("Number of sent Rmsgs: %d\n", stats.sentrmsgs);
    ret += sys->sprint("Number of received Tmsgs: %d\n", stats.recvdtmsgs);
    ret += sys->sprint("Number of received Rmsgs: %d\n", stats.recvdrmsgs);
    ret += sys->sprint("Incoming msgs processing errors: %d\n", stats.processerrors);
    ret += sys->sprint("Send error count: %d\n", stats.senderrors);
    ret += sys->sprint("Sent msgs by type:\n");
    for (i := 0; i < Dht->Tmax - 100; i++)
        ret += sys->sprint("\t%s\t%d\n", msgnames[i], stats.sentmsgsbytype[i]);
    ret += sys->sprint("Received msgs by type:\n");
    for (i = 0; i < Dht->Tmax - 100; i++)
        ret += sys->sprint("\t%s\t%d\n", msgnames[i], stats.recvmsgsbytype[i]);
    ret += sys->sprint("API calls:\n");
    ret += sys->sprint("\tfindvalue\t%d\n", stats.findvaluecalled);
    ret += sys->sprint("\tfindnode\t%d\n", stats.findnodecalled);
    ret += sys->sprint("\tstore\t%d\n", stats.storecalled);
    ret += sys->sprint("\tping\t%d\n", stats.pingcalled);
    if (stats.answersgot == 0)
        ret += sys->sprint("Average rtt: n/a\n");
    else
        ret += sys->sprint("Average rtt: %f\n", real stats.totalrtt / real stats.answersgot);
    ret += sys->sprint("Answers got: %d\n", stats.answersgot);
    ret += sys->sprint("Store entries expired: %d\n", stats.expiredentries);
    ret += sys->sprint("Unanswered nodes: %d\n", stats.unanswerednodes);
    ret += sys->sprint("Bucket overflowed: %d\n", stats.bucketoverflows);
    ret += sys->sprint("Emitted log entries: %d\n", stats.logentries);
    return ret;
}

createtree()
{
    # TODO: fix permissions
    tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
    tree.create(Qroot, dir("foundvalues",   Sys->DMDIR | 8r555, Qfoundvalues));
    tree.create(Qroot, dir("status",        8r760, Qstatus));
    tree.create(Qroot, dir("rpcfindnode",   8r760, Qfindnode));
    tree.create(Qroot, dir("rpcfindvalue",  8r760, Qfindvalue));
    tree.create(Qroot, dir("rpcstore",      8r220, Qstore));
    tree.create(Qroot, dir("rpcping",       8r760, Qping));
    tree.create(Qroot, dir("stats",         8r760, Qstats));
    tree.create(Qroot, dir("localstore",    8r760, Qlocalstore));
    tree.create(Qroot, dir("ourstore",      8r760, Qourstore));
    tree.create(Qroot, dir("contacts",      8r760, Qcontacts));
    tree.create(Qroot, dir("node",          8r760, Qnode));
}

loadmodules()
{
    sys = load Sys Sys->PATH;
    ip = load IP IP->PATH;
    if (ip == nil)
        badmodule(IP->PATH);
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
        badmodule(Keyring->PATH);
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
    bigkey = load Bigkey Bigkey->PATH;
    if (bigkey == nil)
        badmodule(Bigkey->PATH);
    bigkey->init();
    hashtable = load Hashtable Hashtable->PATH;
    if (hashtable == nil)
        badmodule(Hashtable->PATH);
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
        badmodule(Daytime->PATH);
    dht = load Dht Dht->PATH;
    if (dht == nil)
        badmodule(Dht->PATH);
    dht->init();
}

init(nil: ref Draw->Context, args: list of string)
{
    loadmodules();

    # setup a pipe
    fds := array [2] of ref Sys->FD;
    if(sys->pipe(fds) < 0)
    {
        sys->fprint(stderr, "dhtfs: can't create pipe: %r\n");
        raise "fail:pipe";
    }

    bootstrapfile, localaddr: string;
    # get some usefull things
    user = getcuruser();
    stderr = sys->fildes(2);

    # parse cmdline args
    arg := load Arg Arg->PATH;
    if(arg == nil)
        badmodule(Arg->PATH);
    arg->init(args);
    flags := Sys->MREPL;
    copt := 0;
    while((o := arg->opt()) != 0)
        case o {
        'a' =>  flags = Sys->MAFTER;
        'b' =>  flags = Sys->MBEFORE;
        'c' =>  copt = 1;
        'D' =>  styxservers->traceset(1);
        * =>        usage();
        }
    args = arg->argv();
    arg = nil;

    if(len args != 3)
        usage();
    if(copt)
        flags |= Sys->MCREATE;
    localaddr = hd args;
    args = tl args;
    bootstrapfile = hd args;
    args = tl args;
    mountpt := hd args;
    args = tl args;

    # setup styx servers
    navop: chan of ref Styxservers->Navop;
    (tree, navop) = nametree->start();
    nav = Navigator.new(navop);
    (tchan, srv) := Styxserver.new(fds[0], nav, Qroot);
    # prepare find results table
    findresults = hashtable->new(HASHSIZE, array [0] of byte);
    createtree();

    # start dht
    fd := sys->open(bootstrapfile, Sys->OREAD);
    if (fd == nil)
    {
        sys->fprint(stderr, "dhtfs:fatal:bootstrap file not found");
        raise "fail:bootstrap file not found"; 
    }
    buf := array [8192] of byte;
    readbytes := sys->read(fd, buf, len buf);
    if (readbytes < 0)
    {
        sys->fprint(stderr, "dhtfs:fatal:bootstrap file io error");
        raise "fail:bootstrap file io error";
    }
    straplist := strapparse(string buf[:readbytes]);

    # TODO: fix logfd - initial logging
    local = dht->start(localaddr, straplist, Key.generate(), nil);
    if (local == nil)
    {
        sys->fprint(stderr, "dht:fatal:%r");
        raise sys->sprint("fail:dht:%r");
    }

    # start server message processing
    spawn serverloop(tchan, srv);

    # mount our server somewhere
    if(sys->mount(fds[1], nil, mountpt, flags, nil) < 0)
    {
        sys->fprint(stderr, "dhtfs:fatal:mount failed: %r\n");
        raise "fail:mount";
    }

    # start logfile
    readychan := chan of int;
    spawn startlogfile(mountpt + "/log", readychan);

    <-readychan; # wait for logfile to start
    logfile := sys->open(mountpt + "/log", Sys->OWRITE);
    local.setlogfd(logfile);
}

initwithdht(newlocal: ref Local, mountpt: string, flags: int, debug: int)
{
    loadmodules();
    local = newlocal;
    extlocal = 1;

    # setup a pipe
    fds := array [2] of ref Sys->FD;
    if(sys->pipe(fds) < 0)
    {
        sys->fprint(stderr, "dhtfs: can't create pipe: %r\n");
        raise "fail:pipe";
    }

    # get some usefull things
    user = getcuruser();
    stderr = sys->fildes(2);

    if (debug != 0)
        styxservers->traceset(1);

    # setup styx servers
    navop: chan of ref Styxservers->Navop;
    (tree, navop) = nametree->start();
    nav = Navigator.new(navop);
    (tchan, srv) := Styxserver.new(fds[0], nav, Qroot);
    createtree();

    # start server message processing
    spawn serverloop(tchan, srv);

    # mount our server somewhere
    if(sys->mount(fds[1], nil, mountpt, flags, nil) < 0)
    {
        sys->fprint(stderr, "dhtfs:fatal:mount failed: %r\n");
        raise "fail:mount";
    }

    # start logfile
    readychan := chan of int;
    spawn startlogfile(mountpt + "/log", readychan);

    <-readychan; # wait for logfile to start
    logfile := sys->open(mountpt + "/log", Sys->OWRITE);
    local.setlogfd(logfile);
}

# parse bootstrap file
strapparse(s: string): array of ref Node
{
    (nil, strings) := sys->tokenize(s, "\n");
    if (len strings == 0)
        return nil;
    ret := array [len strings] of ref Node;
    i := 0;
    for (it := strings; it != nil; it = tl it)
    {
        sys->fprint(stderr, "Parsing bootstrap entry: %s\n", hd it);
        (nil, blocks) := sys->tokenize(hd it, " ");
        if (blocks == nil || len blocks != 2 || (hd blocks)[:1] == "#")
            continue;
        strapaddr := hd tl blocks;
        strapid := *Key.parse(hd blocks);
        ret[i++] = ref Node(strapid, strapaddr, strapaddr, 
                                       strapaddr, strapid);
    }
    return ret[:i];
}

# styx server loop
serverloop(tchan: chan of ref Styx->Tmsg, srv: ref Styxserver)
{
    for (;;) {
        gm := <-tchan;
        if (gm == nil) {
            tree.quit();
            destroy();
            exit;
        }
        e := handlemsg(gm, srv, tree);
        if (e != nil)
            srv.reply(ref Rmsg.Error(gm.tag, e));
    }
}

# handle server messages
handlemsg(gm: ref Styx->Tmsg, srv: ref Styxserver, nil: ref Tree): string
{
    pick m := gm {
    Read =>
        (fid, err) := srv.canread(m);
        if(fid == nil)
            return err;

        if((fid.qtype & Sys->QTDIR) != 0)
        {
            # dir reads are handled by server
            srv.read(m);
            return nil;
        }

        if (len fid.data != 0)
        {
            srv.reply(readbytes(m, fid.data));
            return nil;
        }

        answer := "you haven't asked a question. 42";
        case fid.path {
            Qstatus =>
                answer = "Here'll come status report";
            Qstats =>
                answer = getstats(local);
            Qlocalstore =>
                answer = storetext(local.store);
            Qourstore =>
                answer = storetext(local.ourstore);
            Qnode =>
                answer = (ref local.node).text() + "\n";
            Qcontacts =>
                answer = local.contacts.text(0);
            * =>
                # do nothing
        }

        fid.data = array of byte answer;
        srv.reply(readstr(m, answer));
    Write =>
        (fid, err) := srv.canwrite(m);
        if (fid == nil)
            return err;
        if (fid.qtype & Sys->QTDIR)
            return Eperm;

        {
            result := "";
            case fid.path {
                Qfindnode =>
                    node := local.dhtfindnode(getkey(m.data), nil);
                    if (node != nil)
                        result = "Node found! " + node.text() + "\n";
                    else
                        result = "Nothing was found\n";
                Qfindvalue =>
                    items := local.dhtfindvalue(getkey(m.data));
                    keystr := string m.data[:Bigkey->BB*2];
                    # fill the foundvalues dir with results
                    rootqid := Qlastfolder;
                    tree.create(Qfoundvalues, dir(keystr, Sys->DMDIR | 8r760, Qlastfolder++));
                    if (items != nil)
                    {
                        idx := 0;
                        for (tail := items; tail != nil; tail = tl tail)
                        {
                            # remember it so we can later retreive it (see Open) or delete it
                            findresults.insert(string Qlastfolder, (hd tail).data);
                            entry := dir(string idx++, 8r760, Qlastfolder++);
                            entry.mtime = (hd tail).publishtime;
                            entry.length = big len (hd tail).data;
                            tree.create(rootqid, entry);
                        }
                        result = tree.getpath(rootqid);
                    }
                    else
                        result = "<null>";
                Qstore =>
                    # fire rpc on clunk, see below
                    if (int m.offset < 0)
                        return Eoffset;
                    # extend the fid.data if needed
                    upperbound := int m.offset + len m.data;
                    if (upperbound > len fid.data)
                    {
                        newdata := array [upperbound] of byte;
                        newdata[:] = fid.data[:];
                        fid.data = newdata;
                    }
                    # store the data in fid.data
                    fid.data[int m.offset:] = m.data[:];
                    # prevent this function to process normally
                    srv.reply(ref Rmsg.Write(m.tag, len m.data));
                    return nil;
                Qping =>
                    key := getkey(m.data);
                    node := local.contacts.getnode(key);
                    if (node == nil)
                        raise "fail:node not found";
                    rtt := local.dhtping(key);
                    if (rtt > 0)
                        result = "Ping success!\nGot answer in " + string rtt + " ms\n";
                    else
                        result = "No answer!\n";
                * => 
                    return Eperm;
            }
            fid.data = array of byte result;
        }
        exception e
        {
            "fail:*" =>
                fid.data = array of byte sys->sprint("Command failed: %s\n", e[5:]);
        }
        # now we have the query result in fid.data, continue happily
        srv.reply(ref Rmsg.Write(m.tag, len m.data));
    Open =>
        fid := srv.open(m);
        if (fid == nil)
            return nil;
        # check if we already have some data for that open
        data := findresults.find(string fid.path);
        # store for later retreival
        if (data != nil)
            fid.data = data;
    Clunk =>
        fid := srv.getfid(m.fid);
        if (fid == nil)
            return Ebadfid;

        case fid.path {
            Qstore =>
                # actually fire dhtstore
                hdata := fid.data;
                keydata := array [keyring->SHA1dlen] of byte;
                keyring->sha1(hdata, len hdata, keydata, nil);
                key := Key(keydata[:Bigkey->BB]);
                local.dhtstore(key, hdata);
        }
        srv.clunk(m);
    Remove =>
        fid := srv.getfid(m.fid);
        if (fid == nil)
            return Ebadfid;
        # allow to delete only findvalue result folders
        if (fid.path < Qfirstfolder)
            return Eperm;
        tree.remove(fid.path);
        srv.delfid(fid);
        srv.reply(ref Rmsg.Remove(m.tag));
    * =>
        srv.default(gm);
    }
    return nil;
}

# start logfile and get it's pid
startlogfile(mountpt: string, readychan: chan of int)
{
    logfilepid = sys->pctl(Sys->NEWPGRP, nil);
    logfile := load Logfile "/dis/logfile.dis";
    if (logfile == nil)
        badmodule("/dis/logfile.dis");
    #sys->fprint(stderr, "Starting logfile on %s\n", mountpt); - not actually an error ;)
    logfile->init(nil, "logfile" :: mountpt :: nil);
    readychan <-= 1;
    readychan <-= 13; # the second one for waiting
}

# finish dhtfs
destroy()
{
    sys->fprint(stderr, "Destroying...\n");
    # kill logfile
    killgroup(logfilepid);
    # close dht
    if (!extlocal)
        local.destroy();
}

# some helper functions

getkey(data: array of byte): Bigkey->Key
{
    keystr := string data;
    if (len keystr < Bigkey->BB*2)
        raise "fail:bad key:" + keystr;
    keystr = keystr[:Bigkey->BB*2];
    key := Key.parse(keystr);
    if (key == nil)
        raise "fail:bad key" + keystr;
    return *key;
}

storetext(store: ref HashTable[list of ref StoreItem]): string
{
    if (store == nil || len store.all() == 0)
    {
        return sys->sprint("<empty>\n");
    }
    ret: string;
    for (rest := store.all(); rest != nil; rest = tl rest)
    {
        for (tail := (hd rest).val; tail != nil; tail = tl tail)
        {
            item := hd tail;
            ret += sys->sprint("%s: data[%d], %s, %s\n", (hd rest).key, len item.data,
                       daytime->text(daytime->gmt(item.lastupdate)),
                       daytime->text(daytime->gmt(item.publishtime)));
        }
    }
    return ret;
}

killgroup(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "killgrp");
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
    # TODO: get this right
    d.uid = user;
    d.gid = user;
    d.qid.path = qid;
    if (perm & Sys->DMDIR)
        d.qid.qtype = Sys->QTDIR;
    else
        d.qid.qtype = Sys->QTFILE;
    d.mode = perm;
    return d;
}
