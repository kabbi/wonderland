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

Qroot, Qcheshire, Qwelcome, Qaddserver, Qbootstrap: con big iota;
Qlast: big;

local: ref Local;

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

init(nil: ref Draw->Context, args: list of string)
{
    if (len args < 2)
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
    localaddr = args[1];
    # find out the current user to make it the owner of all folders
    user = getcuruser();

	# creating navigators and servers
	navop: chan of ref Styxservers->Navop;
	(tree, navop) = nametree->start();
	nav = Navigator.new(navop);
	(tchan, srv) := Styxserver.new(sys->fildes(0), nav, Qroot);

	# creating file tree
	tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
	tree.create(Qroot, dir("cheshire", Sys->DMDIR | 8r555, Qcheshire));
	tree.create(Qcheshire, dir("welcome", 8r555, Qwelcome));
	tree.create(Qcheshire, dir("addserver", 8r777, Qaddserver));
    if (len args == 2)
	    tree.create(Qcheshire, dir("bootstrap", 8r755, Qbootstrap));
    else
    {
    	fd := sys->open(args[2], Sys->OREAD);
        if (fd == nil)
            raise "fail:bootstrap file not found";
        buf := array [8192] of byte;
        readbytes := sys->read(fd, buf, len buf);
        if (readbytes <= 0)
            raise "fail:bootstrap file not found";
    	straplist = strapparse(buf);
        local = start(localaddr, straplist, localkey);
    }
	Qlast = Qbootstrap + big 1;

	# starting message processing loop
	for (;;) {
		gm := <-tchan;
		if (gm == nil) {
			tree.quit();
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
				(answer, request) = writestring(m);
                straplist = strapparse(request);
                local = start(localaddr, straplist, localkey);
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
    (nil, strings) := tokenize(s, "\n");
    ret := array [len strings] of ref Node;
    for (i := 0; i < len strings; ++i)
    {
        (nil, blocks) := tokenize(strings[i], " ");
        if (len blocks != 2)
            raise "fail:malformed bootstrap file";
        ret[i] = Node(Key.parse(blocks[0]), blocks[1], 0);
    }
    return ret;
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
