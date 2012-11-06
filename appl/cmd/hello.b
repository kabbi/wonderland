implement Hello;

include "sys.m";
	sys: Sys;
include "draw.m";

Hello: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

connectString: con "udp!192.168.1.255!13753";

init(ctxt: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	sys->print("hello, world!\n");
	connect := sys->open("/net/cs", Sys->ORDWR);
	if (connect == nil) {
		sys->print("unable to cs, try ndb/cs\n");
		raise "fail:cs";
	}
	sys->fprint(connect, connectString);
	responce := readfile(connect);
	sys->print("%s", responce);
}

readfile(fd: ref Sys->FD): string
{
	if(fd == nil)
		return nil;

	buf := array[1024] of byte;
	n := sys->read(fd, buf, len buf);
	if(n < 0)
		return nil;

	return string buf[0:n];	
}