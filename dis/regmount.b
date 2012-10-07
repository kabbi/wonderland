implement Regmount;

include "sys.m";
	sys: Sys;
include "string.m";
include "keyring.m";
include "draw.m";
include "security.m";
include "ip.m";
	ip: IP;
	IPaddr, Udphdr: import ip;

stderr: ref Sys->FD;
Udphdrsize: con IP->Udphdrlen;
Virgilport: con 6680;

Regmount: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

#
#  Call with first element of argv an arbitrary string, which is
#  discarded here.  argv must also contain at least a question.
#
init(ctxt: ref Draw->Context, argv: list of string)
{
	responce : IPaddr;
	s,request,reply : string;
	timerpid, readerpid: int;

	sys = load Sys Sys->PATH;
	str := load String String->PATH;
	if(str == nil){
		cantload(String->PATH);
		return;
	}
	ip = load IP IP->PATH;
	if(ip == nil){
		cantload(IP->PATH);
		return;
	}
	ip->init();
	stderr = sys->fildes(2);

	(ok, c) := sys->announce("udp!*!0");
	if(ok < 0) {
		sys->fprint(stderr, "failed to open port");
		return;
	}
	if(sys->fprint(c.cfd, "headers") < 0) {
		sys->fprint(stderr, "failed to set headers\n");
		return;
	}
	c.dfd = sys->open(c.dir+"/data", sys->ORDWR);
	if(c.dfd == nil) {
		sys->fprint(stderr, "failed to open data\n");
		return;
	}

	sys->fprint(stderr, "ok, loaded\n");
	readerchan := chan of IPaddr;
	timerchan := chan of int;
	readerpidchan := chan of int;

	spawn timer(timerchan);
	timerpid = <-timerchan;
	spawn reader(c.dfd, readerchan, readerpidchan);
	readerpid = <-readerpidchan;

	request = getid() + " ???";
	qbuf := array of byte request;
	hdr := Udphdr.new();
	hdr.raddr = ip->v4bcast;
	hdr.rport = Virgilport;
	buf := array[Udphdrsize + len qbuf] of byte;
	buf[Udphdrsize:] = qbuf;
	hdr.pack(buf, Udphdrsize);

	if (sys->write(c.dfd, buf, len buf) < 0) {
		sys->fprint(stderr, "broadcast send fail\n");
		return;
	}
	
	done := 0;
	while (1) {

		alt {
		responce = <-readerchan =>
			break;
		<-timerchan =>
			done = 1;
			break;
		};

		if (done)
			break;

		# q and r is in form 'name [!?][!?][!?]'
		sys->print("IP: %s\n", responce.text());
	}

	killpid(readerpid);
	killpid(timerpid);
}

cantload(s: string)
{
	sys->fprint(stderr, "regmount: can't load %s: %r\n", s);
}

getid(): string
{
	fd := sys->open("/dev/sysname", sys->OREAD);
	if(fd == nil)
		return "unknown";
	buf := array[256] of byte;
	n := sys->read(fd, buf, len buf);
	if(n < 1)
		return "unknown";
	return string buf[0:n];
}

reader(fd: ref sys->FD, cstring: chan of IPaddr, cpid: chan of int)
{
	pid := sys->pctl(0, nil);
	cpid <-= pid;

	buf := array[2048] of byte;

	while (1) {
		n := sys->read(fd, buf, len buf);
		if(n <= Udphdrsize)
			continue;

		# dump cruft
		for(i := Udphdrsize; i < n; i++)
			if((int buf[i]) == 0)
				break;

		sys->print("Answer from: %s\n", string buf[Udphdrsize:i]);
		hdr := Udphdr.unpack(buf, len buf);
		cstring <-= hdr.raddr;
	}
}

timer(c: chan of int)
{
	pid := sys->pctl(0, nil);
	c <-= pid;
	sys->sleep(5000);
	c <-= 1;
}

killpid(pid: int)
{
	fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "kill");
}
