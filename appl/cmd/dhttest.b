implement Dhttest;
include "sys.m";
	sys: Sys;
include "draw.m";
include "daytime.m";
include "bigkey.m";
	bigkey: Bigkey;
	Key: import bigkey;
include "dht.m";
	dht: Dht;
	Node,Bucket,Contacts,Local,K,BB: import dht;

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
	bigkey = load Bigkey Bigkey->PATH;
	if (bigkey == nil)
		badmodule(Bigkey->PATH);
	bigkey->init();

	local := dht->start("udp!127.0.0.1!1234", ref Node(Key.generate(),
		"nil", 0), Key.generate());
	if (local == nil)
	{
		sys->print("failed to start server!\n%r\n");
		return;
	}
	sys->print("started Dht, local id %s\n", local.node.id.text());

	sys->print("generating some random keys\n");
	key1 := Key.generate();
	key2 := Key.generate();
	sys->print("key1: %s\n", key1.text());
	sys->print("key2: %s\n", key2.text());
	sys->print("key1 lt key2 = %d\n", key1.lt(key2));
	sys->print("key2 lt key1 = %d\n", key2.lt(key1));
	sys->print("key1 gt key2 = %d\n", key1.gt(key2));
	sys->print("key2 gt key1 = %d\n", key2.gt(key1));
	sys->print("\n");

	sys->print("generating some random nodes\n");
	node1 := ref Node(key1, "addr1", 0);
	node2 := ref Node(key2, "addr2", 0);
	sys->print("node1: %s\n", node1.text());
	sys->print("node2: %s\n", node2.text());
	sys->print("\n");

	sys->print("adding them to the contacts\n");

	local.contacts.addcontact(node1);
	local.contacts.addcontact(node2);
	local.contacts.addcontact(node1);
	local.contacts.addcontact(node2);

	sys->print("contacts after adding 2 nodes:\n");
	local.contacts.print(0);
	sys->print("\n");

	local.contacts.removecontact(node1.id);
	local.contacts.removecontact(node2.id);
	# currently fails if deletes non-existant node
	#local.contacts.removecontact(node2.id);
	#local.contacts.removecontact(node1.id);

	sys->print("contacts after removing 2 nodes:\n");
	local.contacts.print(0);
	sys->print("\n");

	sys->print("trying to get K closest to the random node\n");
	randkey := Key.generate();
	# to have something in contacts
	for (i := 0; i < 200000; i++)
	{
		node := ref Node(Key.generate(), "addrfx" + string i, 0);
		local.contacts.addcontact(node);
	}
	#local.contacts.print(0);
	sys->print("looking for key: %s\n", randkey.text());
	closest := local.contacts.findclosenodes(randkey);
	for (i = 0; i < len closest; i++)
	{
		sys->print("%s - dist ", (ref closest[i]).text());
		dist := closest[i].id;
		for (j := 0; j < BB; j++)
			dist.data[j] ^= randkey.data[j];
		sys->print("%s\n", dist.text());
	}
	sys->print("\n");

	sys->print("checking randomidinbucketrange on 100000 random ids\n");
	minrange := Key.generate();
	maxrange := Key.generate();
	if (maxrange.lt(minrange))
	{
		temp := maxrange;
		maxrange = minrange;
		minrange = temp;
	}
	bucket := ref Bucket(array [0] of Node, minrange, maxrange,
        local.contacts.buckets[0].lastaccess);
	local.contacts.buckets = array [1] of {bucket};
	for (i = 0; i < 100000; i++)
	{
		key := local.contacts.randomidinbucket(0);
		if (!bucket.isinrange(key))
		{
			sys->print("noooo, it failed on key %s :(\n", key.text());
			raise "fail:test failed";
		}
	}
	sys->print("ok!\n");
	sys->print("\n");

	# recreate everything...
	local.destroy();
	local = dht->start("udp!127.0.0.1!1234", ref Node(Key.generate(),
		"nil", 0), Key.generate());

	sys->print("adding 100000 random keys\n");
	for (i = 0; i < 100000; i++)
	{
		node := ref Node(Key.generate(), "addrx" + string i, 0);
		local.contacts.addcontact(node);
	}
	nodecount := 0;
	for (i = 0; i < len local.contacts.buckets; i++)
		nodecount += len local.contacts.buckets[i].nodes;
	sys->print("surprisingly, finished ok! added %d keys\n", nodecount);
	sys->print("\n");

	# recreate everything...
	local.destroy();
	local = dht->start("udp!127.0.0.1!1234", ref Node(Key.generate(),
		"nil", 0), Key.generate());

	sys->print("adding 160*K sequential keys\n");
	for (i = 0; i < 160; i++)
	{
		for (j := 0; j < K; j++)
		{
			idx := local.contacts.findbucket(local.node.id);
			node := ref Node(local.contacts.randomidinbucket(idx),
				"addrn" + string i, 0);
			local.contacts.addcontact(node);
		}
	}
	nodecount = 0;
	for (i = 0; i < len local.contacts.buckets; i++)
		nodecount += len local.contacts.buckets[i].nodes;
	sys->print("again surprisingly, finished ok! added %d keys\n", nodecount);
	sys->print("number of buckets: %d\n", len local.contacts.buckets);
	sys->print("\n");

	sys->print("trying to fill the whole routing table\n");
	for (i = 0; i < len local.contacts.buckets; i++)
	{
		for (j := 0; j < K; j++)
		{
			node := ref Node(local.contacts.randomidinbucket(i), "addrq", 0);
			local.contacts.addcontact(node);
		}
	}
	nodecount = 0;
	for (i = 0; i < len local.contacts.buckets; i++)
		nodecount += len local.contacts.buckets[i].nodes;
	sys->print("total count of contacts: %d\n", nodecount);
	sys->print("\n");

	sys->print("cleaning up\n");
	local.destroy();
}