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
	Ebadfid, Enotfound, Eopen, Einuse: import Styxservers;
	Styxserver, readbytes, Navigator, Fid: import styxservers;
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
include "dht.m";
    dht: Dht;
    Node, Local, StoreItem: import dht;

Dhtfs: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};
Logfile: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

Qroot: con big 16rfffffff;
Qfindnode, Qfindvalue, Qstore, Qping,
Qstats, Qstatus, Qlocalstore, Qcontacts: con big iota + big 16r42;
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
		'a' =>	flags = Sys->MAFTER;
		'b' =>	flags = Sys->MBEFORE;
		'c' =>	copt = 1;
		'D' =>	styxservers->traceset(1);
		* =>		usage();
		}
	args = arg->argv();
	arg = nil;

	if(len args != 3)
		usage();
	if(copt)
		flags |= Sys->MCREATE;
	localaddr := hd args;
	args = tl args;
	bootstrapfile := hd args;
	args = tl args;
	mountpt := hd args;

	# setup styx servers
	navop: chan of ref Styxservers->Navop;
	(tree, navop) = nametree->start();
	nav = Navigator.new(navop);
	(tchan, srv) := Styxserver.new(fds[0], nav, Qroot);

	# TODO: fix permissions
	# create our file tree
	tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
	tree.create(Qroot, dir("findnode",		8r555, Qfindnode));
	tree.create(Qroot, dir("findvalue",		8r555, Qfindvalue));
	tree.create(Qroot, dir("store",			8r555, Qstore));
	tree.create(Qroot, dir("ping", 			8r555, Qping));
	tree.create(Qroot, dir("stats",			8r555, Qstats));
	tree.create(Qroot, dir("status",		8r555, Qstatus));
	tree.create(Qroot, dir("localstore",	8r555, Qlocalstore));
	tree.create(Qroot, dir("contacts",		8r555, Qcontacts));

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

	# start dht
    fd := sys->open(bootstrapfile, Sys->OREAD);
    if (fd == nil)
        raise "fail:bootstrap file not found";
    buf := array [8192] of byte;
    readbytes := sys->read(fd, buf, len buf);
    if (readbytes < 0)
        raise "fail:bootstrap file io error";
    sys->fprint(stderr, "Parsing bootstrap\n");
    straplist := strapparse(string buf[:readbytes]);

    <-readychan; # wait for logfile to start
	logfile := sys->open(mountpt + "/log", Sys->OWRITE);
	local = dht->start(localaddr, straplist, Key.generate(), logfile);
	if (local == nil)
    {
        sys->fprint(stderr, "dhtfs: too bad, dht init error: %r\n");
        raise sys->sprint("fail:dht:%r");
    }
    sys->fprint(stderr, "Dht started!\n");
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
        ret[i++] = ref Node(*Key.parse(hd blocks), hd tl blocks, 0);
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
