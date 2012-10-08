implement Cheshire;
include "sys.m";
	sys: Sys;
include "draw.m";
include "styx.m";
	styx: Styx;
	Rmsg, Tmsg: import styx;
include "styxservers.m";
	styxservers: Styxservers;
	Ebadfid, Enotfound, Eopen, Einuse: import Styxservers;
	Styxserver, readbytes, Navigator, Fid: import styxservers;

	nametree: Nametree;
	Tree: import nametree;

Cheshire: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

# Qroot: con big 16rfffffff;

badmodule(p: string)
{
	sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
	raise "fail:bad module";
}
DEBUG: con 0;

Entry: adt {
	refcount: int;
	path: big;
};
refcounts := array[10] of Entry;
tree: ref Tree;
nav: ref Navigator;

uniq: int;

Qroot, Qwelcome, Qnothing: con big iota;
init(nil: ref Draw->Context, nil: list of string)
{
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

	# creating navigators and servers
	navop: chan of ref Styxservers->Navop;
	(tree, navop) = nametree->start();
	nav = Navigator.new(navop);
	(tchan, srv) := Styxserver.new(sys->fildes(0), nav, Qroot);

	# creating file tree
	tree.create(Qroot, dir(".", Sys->DMDIR | 8r555, Qroot));
	tree.create(Qroot, dir("Hello! Welcome to wonderland!", 8r555, Qwelcome));
	tree.create(Qroot, dir("No wonders right now, more content later...", 8r555, Qnothing));
	

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
	* =>
		srv.default(gm);
	}
	return nil;
}

Blankdir: Sys->Dir;
dir(name: string, perm: int, qid: big): Sys->Dir
{
	d := Blankdir;
	d.name = name;
	d.uid = "me";
	d.gid = "me";
	d.qid.path = qid;
	if (perm & Sys->DMDIR)
		d.qid.qtype = Sys->QTDIR;
	else
		d.qid.qtype = Sys->QTFILE;
	d.mode = perm;
	return d;
}
