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
include "security.m";
    random: Random;
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

	nametree: Nametree;
	Tree: import nametree;

Cheshire: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

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

stderr: ref Sys->FD;
dhtlogfd: ref Sys->FD;
mainpid: int;

Qroot, Qcheshire, Qwelcome, Qaddserver, Qbootstrap, Qdhtlog, Qlastpath: con big iota;
Qlast: big;

local: ref Local;

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

startdht()
{
	dhtlogfd = sys->create(sys->sprint("/tmp/%ddhtlog.log", mainpid), Sys->ORDWR, 8r700);
    local = dht->start(localaddr, straplist, localkey);
    if (local == nil)
    {
    	sys->fprint(stderr, "Very bad, dht init error: %r\n");
    	raise sys->sprint("fail:dht:%r");
    }
    if (dhtlogfd != nil)
    {
    	local.setlogfd(dhtlogfd);
    	sys->fprint(stderr, "Dht logging started\n");
    }
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
    dht = load Dht Dht->PATH;
    if (dht == nil)
        badmodule(Dht->PATH);
    dht->init();
    bigkey = load Bigkey Bigkey->PATH;
    if (bigkey == nil)
        badmodule(Bigkey->PATH);
    bigkey->init();

    localkey = Key.generate();
    localaddr = hd args;
    # find out the current user to make it the owner of all folders
    user = getcuruser();
    stderr = sys->fildes(2);
    mainpid = sys->pctl(0, nil);

	# creating navigators and servers
    sys->fprint(stderr, "Creating styxservers\n");
	navop: chan of ref Styxservers->Navop;
	(tree, navop) = nametree->start();
	nav = Navigator.new(navop);
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

	# starting message processing loop
	for (;;) {
		gm := <-tchan;
		if (gm == nil) {
			tree.quit();
			if (local != nil)
				local.destroy();
			exit;
		}
		e := handlemsg(gm, srv, tree);
		if (e != nil)
			srv.reply(ref Rmsg.Error(gm.tag, e));
	}
}

handlemsg(gm: ref Styx->Tmsg, srv: ref Styxserver, nil: ref Tree): string
{
	pick m := gm {
	# some processing will be here some day...
	# now just let the server handle everything
	Read =>
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
				c.data = array of byte ("You typed: " + request);
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
	#Walk =>
	#	tree.create(Qroot, dir(, Sys->DMDIR | 8r555, Qlast));
	#	Qlast = Qlast + big 1;
	#	srv.walk(m);
	* =>
		srv.default(gm);
	}
	return nil;
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
