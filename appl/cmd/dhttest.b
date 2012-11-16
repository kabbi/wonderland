implement dhttest;
include "sys.m";
	sys: Sys;
include "draw.m";
include "daytime.m";
    daytime: Daytime;
include "bigkey.m";
	bigkey: Bigkey;
	Key: import bigkey;
include "dht.m";
	dht: Dht;
	Node,Bucket,Contacts,Local,K,BB: import dht;

dhttest: module {
	init: fn(nil: ref Draw->Context, argv: list of string);
};

badmodule(p: string)
{
	sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
	raise "fail:bad module";
}

local: ref Local;

dist(k1, k2: Key): Key
{
    r := Key.generate();
    r.data[:] = k1.data[:];
    for (i := 0; i < BB; i++)
        r.data[i] ^= k2.data[i];
    return r;
}

initlocal(verbose: int): ref Local
{
	l := dht->start("udp!127.0.0.1!1234", ref Node(Key.generate(),
		"nil", 0), Key.generate());
	if (l == nil)
	{
		sys->print("failed to start server!\n%r\n");
        raise "fail:failed to start server";
	}
    if (verbose)
    	sys->print("started Dht, local id %s\n", l.node.id.text());
    return l;
}

clean(verbose: int): int
{
    if (verbose)
        sys->print("Cleaning local...\n");
    contacts := ref Contacts(array [1] of ref Bucket, Key.generate());
    contacts.buckets[0] = ref Bucket(array [0] of Node,
        Key(array[BB] of { * => byte 0 }),
        Key(array[BB] of { * => byte 16rFF }),
        *daytime->local(daytime->now()));
        local.contacts = contacts;
    if (verbose)
        sys->print("OK. Local cleaned\n");
    return 0;
}

print()
{
    local.contacts.print(0);
    sys->print("\n");
}

addnode(key: Key, verbose: int)
{
    local.contacts.addcontact(ref Node(key, "explicit", 0));
    if (verbose)
        sys->print("Key successfully added.\n");
}

addrandom(verbose: int): Key
{
    key := Key.generate();
    local.contacts.addcontact(ref Node(key, "random", 0));
    if (verbose)
        sys->print("Added key with id:%s\n", key.text());
    return key;
}

removekey(key: Key, verbose: int)
{
    if (verbose)
        sys->print("Deleting node\n");
    if (local.contacts.buckets[local.contacts.findbucket(key)].findnode(key) == -1)
    {
        if (verbose)
            sys->print("Not found!\n");
        return;
    }
    local.contacts.removecontact(key);
    if (verbose)
        sys->print("Successfully deleted\n");
}

countnodes(verbose: int): int
{
    count := 0;
    for (i := 0; i < len local.contacts.buckets; i++)
        count += len local.contacts.buckets[i].nodes;
    if (verbose)
        sys->print("Node count: %d\n", count);
    return count;
}

addrandoms(num: int, verbose: int): array of Key
{
    keys := array[num] of Key;
    if (verbose)
        sys->print("Adding random nodes\n");
    for (i := 0; i < num; ++i)
        keys[i] = addrandom(verbose);
    if (verbose)
        sys->print("Nodes added: %d\n", num);
    return keys;
}

closest(key: Key, verbose: int): array of Node
{
    if (verbose)
        sys->print("looking for key: %s\n", key.text());
	close := local.contacts.findclosenodes(key);
	for (i := 0; i < len close && verbose; i++)
	{
		sys->print("Distance from %s = ", (ref close[i]).text());
		sys->print("%s\n", dist(close[i].id, key).text());
	}
    return close;
}

# Tests

closesttest(count: int)
{
    local.destroy();
    local = initlocal(0);
    sys->print("trying to get K closest to the random node\n");
    addrandoms(count, 0);
    randomid := Key.generate();
    close := closest(randomid, 0);
    b := Bucket(close, Key.generate(), Key.generate(), 
                       *daytime->local(daytime->now()));
    for (k := 0; k < len close; ++k)
    {
        d := dist(randomid, close[k].id);
        for (i := 0; i < len local.contacts.buckets; ++i)
            for (j := 0; j < len local.contacts.buckets[i].nodes; ++j)
            {
                curnode := local.contacts.buckets[i].nodes[j];
                if (dist(curnode.id, randomid).lt(d) 
                      && 
                    ((ref b).findnode(curnode.id) == -1))
                {
                    sys->print("Closest test failed!\n");
                    sys->print("getclosenodes returned:\n");
                    (ref b).print(0);
                    sys->print("... but %s is nearer to\n", 
                                        curnode.id.text());
                    sys->print("        %s (randomly picked node) then\n",
                                        randomid.text());
                    sys->print("        %s\n",
                                        close[k].id.text());
                    sys->print("d(conflict, random) = %s\n", dist(curnode.id, randomid).text());
                    sys->print("d(closest, random) =  %s\n", d.text());
                    raise "test fail:closest";
                }
            }
    }
    sys->print("OK! Closest test passed!\n");
	sys->print("\n");
}

randomidinrangetest(count: int) 
{
    local.destroy();
    local = initlocal(0);
	sys->print("checking randomidinbucketrange on %d random ids\n", count);
    b := Bucket(array[0] of Node, Key.generate(), Key.generate(), 
                                  *daytime->local(daytime->now()));
    sys->print("bucket: \n");
    (ref b).print(0);
    if (b.maxrange.lt(b.minrange))
    {
        tm := b.maxrange;
        b.maxrange = b.minrange;
        b.minrange = tm;
    }
    local.contacts.buckets = array[1] of { ref b };
    for (i := 0; i < count; i++)
	{
		key := local.contacts.randomidinbucket(0);
		if (!(ref b).isinrange(key))
		{
			sys->print("noooo, it failed on key %s :(\n", key.text());
			raise "test fail:randomidinrange";
		}
	}
    sys->print("OK! Randomidinrange test passed!\n");
	sys->print("\n");
}

sequentialtest()
{
    local.destroy();
    local = initlocal(0);
    sys->print("Adding 160*K sequential keys\n");
	for (i := 0; i < 160; i++)
	{
		for (j := 0; j <= K; j++)
		{
			idx := local.contacts.findbucket(local.node.id);
			node := ref Node(local.contacts.randomidinbucket(idx),
				"sequential" + string i, 0);
			local.contacts.addcontact(node);
		}
	}
	sys->print("OK! Sequential-test passed! Added %d keys\n", countnodes(0));
	sys->print("Number of buckets: %d\n", len local.contacts.buckets);
	sys->print("\n");
}

filltest()
{
    local.destroy();
    local = initlocal(0);
    sys->print("Trying to fill the whole routing table\n");
	for (i := 0; i < len local.contacts.buckets; i++)
	{
		for (j := 0; j <= K; j++)
		{
			node := ref Node(local.contacts.randomidinbucket(i), "fill test", 0);
			local.contacts.addcontact(node);
		}
	}
	sys->print("OK! Total count of contacts: %d\n", countnodes(0));
	sys->print("Number of buckets: %d\n", len local.contacts.buckets);
	sys->print("\n");
}

starttest()
{
    local = initlocal(0);
    key1 := addrandom(1);
    key2 := addrandom(1);
    addnode(key1, 1);
    addnode(key2, 1);
    print();
    clean(0);
    keys := addrandoms(100, 1);
    countnodes(1);
    for (i := 0; i < len keys; i++)
        removekey(keys[i], 0);
    if (countnodes(1) != 0)
    {
        sys->print("Deletion test failed!\n");
        raise "test fail:deletion";
    }
    #while (1)
      filltest();
}

init(nil: ref Draw->Context, nil: list of string)
{
	# loading modules
	sys = load Sys Sys->PATH;
	daytime = load Daytime Daytime->PATH;
	if (daytime == nil)
		badmodule(Daytime->PATH);
	
	dht = load Dht Dht->PATH;
	if (dht == nil)
		badmodule(Dht->PATH);
	dht->init();
	bigkey = load Bigkey Bigkey->PATH;
	if (bigkey == nil)
		badmodule(Bigkey->PATH);
	bigkey->init();

    starttest();
	sys->print("cleaning up\n");
	local.destroy();
}
