implement Dhttest;
include "sys.m";
	sys: Sys;
include "draw.m";
include "daytime.m";
include "dht.m";
	dht: Dht;
	Key,Node,Bucket,Contacts,Local: import dht;

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

	local := dht->start("127.0.0.1:1234", ref Node(Key.generate(),
		"nil", 0), Key.generate());

	sys->print("generating some random keys\n");
	key1 := ref Key.generate();
	key2 := ref Key.generate();
	sys->print("key1: %s\n", key1.text());
	sys->print("key2: %s\n", key2.text());
	sys->print("key1 lt key2 = %d\n", key1.lt(key2));
	sys->print("key2 lt key1 = %d\n", key2.lt(key1));
	sys->print("key1 gt key2 = %d\n", key1.gt(key2));
	sys->print("key2 gt key1 = %d\n", key2.gt(key1));
	sys->print("\n");

	sys->print("generating some random nodes\n");
	node1 := ref Node(*key1, "addr1", 0);
	node2 := ref Node(*key2, "addr2", 0);
	sys->print("node1: %s\n", node1.text());
	sys->print("node2: %s\n", node2.text());
	sys->print("\n");

	sys->print("adding them to the contacts\n");
	(ref local.contacts).addcontact(node1);
	(ref local.contacts).addcontact(node2);
	(ref local.contacts).print(0);
	sys->print("\n");

	sys->print("cleaning up\n");
	local.destroy();
}