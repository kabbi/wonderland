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
    Ebadfid, Enotfound, Eopen, Einuse, Eperm: import Styxservers;
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
};
Logfile: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
};

Qroot: con big 16rfffffff;
Qfindnode, Qfindvalue, Qstore, Qping, Qstats, Qstatus, 
Qlocalstore, Qcontacts, Qstart, Qbootstrap, Qnode: con big iota + big 16r42;
dhtstarted := 0;
bootstrapfile, localaddr: string;
logfile: ref Sys->FD;
tree: ref Tree;
nav: ref Navigator;
logfilepid: int;
local: ref Local;

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

init(nil: ref Draw->Context, args: list of string)
{
    # load some modules
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
    dht = load Dht Dht->PATH;
    if (dht == nil)
        badmodule(Dht->PATH);
    dht->init();

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
    mountpt := hd args;
    bootstrapfile = mountpt + "/bootstrap";

    # setup styx servers
    navop: chan of ref Styxservers->Navop;
    (tree, navop) = nametree->start();
    nav = Navigator.new(navop);
    (tchan, srv) := Styxserver.new(fds[0], nav, Qroot);

    # TODO: fix permissions
    # create our file tree
    tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
    tree.create(Qroot, dir("status",        8r764, Qstatus));
    tree.create(Qroot, dir("start",         8r764, Qstart));
    tree.create(Qroot, dir("bootstrap",     8r764, Qbootstrap));

    # start server message processing
    spawn serverloop(tchan, srv);

    # mount our server somewhere
    if(sys->mount(fds[1], nil, mountpt, flags, nil) < 0)
    {
        sys->fprint(stderr, "dhtfs: mount failed: %r\n");
        raise "fail:mount";
    }

    # start logfile
    readychan := chan of int;
    spawn startlogfile(mountpt + "/log", readychan);

    <-readychan; # wait for logfile to start
    logfile = sys->open(mountpt + "/log", Sys->OWRITE);
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
                # TODO: Make it more informative
                if (!dhtstarted)
                    answer = "Dht not started";
                else
                    answer = "Dht started";
            Qstats =>
                answer = "dht statistics";
            Qlocalstore =>
                answer = storetext(local.store);
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
                Qbootstrap =>
                    result = string m.data;
                Qstart =>
                    # start dht
                    fd := sys->open(bootstrapfile, Sys->OREAD);
                    if (fd == nil)
                    {
                        fid.data = array of byte "fail:bootstrap file not found";
                        break;
                    }
                    buf := array [8192] of byte;
                    readbytes := sys->read(fd, buf, len buf);
                    if (readbytes < 0)
                    {
                        fid.data = array of byte "fail:bootstrap file io error";
                        break;
                    }
                    straplist := strapparse(string buf[:readbytes]);

                    local = dht->start(localaddr, straplist, Key.generate(), logfile);
                    if (local == nil)
                    {
                        fid.data = array of byte sys->sprint("fail:dht:%r");
                        break;
                    }
                    fid.data = array of byte sys->sprint("Dht started!\n");
                    tree.remove(Qstart);
                    tree.remove(Qbootstrap);
                    tree.create(Qroot, dir("findnode",      8r764, Qfindnode));
                    tree.create(Qroot, dir("findvalue",     8r764, Qfindvalue));
                    tree.create(Qroot, dir("store",         8r764, Qstore));
                    tree.create(Qroot, dir("ping",          8r764, Qping));
                    tree.create(Qroot, dir("stats",         8r764, Qstats));
                    tree.create(Qroot, dir("localstore",    8r764, Qlocalstore));
                    tree.create(Qroot, dir("contacts",      8r764, Qcontacts));
                    tree.create(Qnode, dir("node",      8r764, Qbootstrap));
                    # TODO: Change the dht model to allow it's existance in default state? (e.g. without starting)
                    dhtstarted = 1;
                Qfindnode =>
                    key := Key.parse(string m.data);
                    if (key == nil)
                        raise "fail:bad key" + string m.data;
                    node := local.dhtfindnode(*key, nil);
                    if (node != nil)
                        result = "Node found! " + node.text() + "\n";
                    else
                        result = "Nothing was found\n";
                Qfindvalue =>
                    key := Key.parse(string m.data);
                    if (key == nil)
                        raise "fail:bad key:" + string m.data;
                    items := local.dhtfindvalue(*key);
                    if (items != nil)
                    {
                        result = "Something found:\n";
                        for (tail := items; tail != nil; tail = tl tail)
                            result += "\t" + string (hd tail).data + "\n";
                    }
                    else
                        result = "Nothing was found\n";
                Qstore =>
                    hdata := array of byte m.data;
                    keydata := array [keyring->SHA1dlen] of byte;
                    keyring->sha1(hdata, len hdata, keydata, nil);
                    key := Key(keydata[:Bigkey->BB]);
                    local.dhtstore(key, hdata);
                    result = "Stored by " + key.text();
                Qping =>
                    id := Key.parse(string m.data);
                    node := local.contacts.getnode(*id);
                    if (id == nil || node == nil)
                        raise "fail:bad key";
                    rtt := local.dhtping(*id);
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
    sys->fprint(stderr, "Starting logfile on %s\n", mountpt);
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
    local.destroy();
}

# some helper functions

storetext(store: ref HashTable[list of ref StoreItem]): string
{
    if (store == nil || len store.all() == 0)
    {
        return sys->sprint("\t<empty>\n");
    }
    ret: string;
    for (rest := store.all(); rest != nil; rest = tl rest)
    {
        for (tail := (hd rest).val; tail != nil; tail = tl tail)
        {
            item := hd tail;
            ret += sys->sprint("\t%s: %s, %s, %s\n", (hd rest).key, string item.data,
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
