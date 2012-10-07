implement Regannounce;

include "sys.m";
sys: Sys;

include "draw.m";

include "ip.m";

Regannounce: module
{
	init:	fn(ctxt: ref Draw->Context, argv: list of string);
};

stderr: ref Sys->FD;
Udphdrsize: con IP->Udphdrlen;
progname: string;

init(ctxt: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;

	stderr = sys->fildes(2);

	sys->pctl(Sys->FORKNS|Sys->FORKFD, nil);
	
	progname = hd argv;
	if (len argv > 1 && hd tl argv == "-d") {
		spawn init(ctxt, list of {progname});
		return;
	}

	for(;;sys->sleep(10*1000)){
		fd := openlisten();
		if(fd == nil)
			return;

		buf := array[512] of byte;
		for(;;){
			n := sys->read(fd, buf, len buf);
			if(n <= Udphdrsize)
				break;
			if(n <= Udphdrsize+1)
				continue;

			# dump any cruft after the device name
			for(i := Udphdrsize; i < n; i++){
				c := int buf[i];
				if(c == ' ' || c == 0 || c == '\n')
					break;
			}

			# answer := query(string buf[Udphdrsize:i]);
			answer := getid() + " !!!";
			if(answer == nil)
				continue;

			# reply
			r := array of byte answer;
			if(len r > len buf - Udphdrsize)
				continue;
			buf[Udphdrsize:] = r;
			sys->write(fd, buf, Udphdrsize+len r);
		}
		fd = nil;
	}
}

openlisten(): ref Sys->FD
{
	(ok, c) := sys->announce("udp!*!registries");
	if(ok < 0){
		sys->fprint(stderr, "registries: can't open port: %r\n");
		return nil;
	}

	if(sys->fprint(c.cfd, "headers") <= 0){
		sys->fprint(stderr, "registries: can't set headers: %r\n");
		return nil;
	}

	c.dfd = sys->open(c.dir+"/data", Sys->ORDWR);
	if(c.dfd == nil) {
		sys->fprint(stderr, "registries: can't open data file\n");
		return nil;
	}
	return c.dfd;
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