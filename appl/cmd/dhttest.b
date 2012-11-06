implement Dhttest;
include "sys.m";
	sys: Sys;
include "draw.m";
include "daytime.m";
include "dht.m";
	dht: Dht;
	Key,Node,Contacts,Local: import dht;

Dhttest: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

badmodule(p: string)
{
	sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
	raise "fail:bad module";
}

init(nil: ref Draw->Context, nil: list of string)
{
	# loading modules
	sys = load Sys Sys->PATH;
	
	dht = load Dht Dht->PATH;
	if (dht == nil)
		badmodule(Dht->PATH);
	dht->init();

	#local := dht->start("127.0.0.1:1234");

	sys->print("generating random key...\n");
	key := Key.generate();
	sys->print("key: %s\n", key.text());
}