implement dhttest;
include "sys.m";
    sys: Sys;
include "draw.m";
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
    Node,Bucket,Contacts,Local,K,BB,B,
    MAXRPC,Rmsg,Tmsg: import dht;

DEFADDR: con "udp!127.0.0.1!10000";

dhttest: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
};

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail:bad module";
}

local: ref Local;

arreq(a1, a2: array of byte): int
{
    if (len a1 != len a2)
        return 0;
    for (i := 0; i < len a1; i++)
        if (a1[i] != a2[i])
            return 0;
    return 1;
}

dist(k1, k2: Key): Key
{
    r := Key.generate();
    r.data[:] = k1.data[:];
    for (i := 0; i < BB; i++)
        r.data[i] ^= k2.data[i];
    return r;
}

initlocal(addr: string, verbose: int): ref Local
{
    port := random->randomint(random->NotQuiteRandom);
    port &= 16rFFFF; # IP port range
    port %= 100; # our port range
    port += 12000;
    if (addr == "")
        addr = "udp!127.0.0.1!" + string port;

    l := dht->start(addr, array [0] of ref Node, Key.generate());
    if (l == nil)
    {
        sys->print("failed to start server!\n%r\n");
        raise "fail:failed to start server";
    }
    if (verbose)
        sys->print("started Dht, local node %s\n", (ref l.node).text());
    return l;
}

clean(verbose: int): int
{
    if (verbose)
        sys->print("Cleaning local...\n");
    contacts := ref Contacts(array [1] of ref Bucket, local);
    contacts.buckets[0] = ref Bucket(array [0] of Node,
    Key(array[BB] of { * => byte 0 }),
    Key(array[BB] of { * => byte 16rFF }),
    daytime->now());
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
    local.contacts.addcontact(ref Node(key, DEFADDR, 0));
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

randomtmsg(): ref Tmsg
{
    msgtype := random->randomint(random->NotQuiteRandom) & 16rFF;
    msgtype = msgtype % 4;

    uid := Key.generate();
    remoteaddr := "nil";
    senderID := Key.generate();
    targetID := Key.generate();

    case msgtype {
        0 =>
            return ref Tmsg.Ping(uid, remoteaddr, senderID, targetID);
        1 =>
            key := Key.generate();
            l := random->randomint(random->NotQuiteRandom) & 16rFF;
            data := random->randombuf(random->NotQuiteRandom, l);
            ask := random->randomint(random->NotQuiteRandom) & 16rFF;
            return ref Tmsg.Store(uid, remoteaddr, senderID, targetID, key, ref Dht->StoreItem(data, 0, 0));
        2 =>
            key := Key.generate();
            return ref Tmsg.FindNode(uid, remoteaddr, senderID, targetID, key);
        3 =>
            key := Key.generate();
            return ref Tmsg.FindValue(uid, remoteaddr, senderID, targetID, key);
    }

    return nil;
}
randomrmsg(): ref Rmsg
{
    msgtype := random->randomint(random->NotQuiteRandom) & 16rFF;
    msgtype = msgtype % 4;

    uid := Key.generate();
    remoteaddr := "nil";
    senderID := Key.generate();
    targetID := Key.generate();

    case msgtype {
        0 =>
            return ref Rmsg.Ping(uid, remoteaddr, senderID, targetID);
        1 =>
            result := random->randomint(random->NotQuiteRandom) & 16rFF;
            return ref Rmsg.Store(uid, remoteaddr, senderID, targetID, result);
        2 =>
            l := random->randomint(random->NotQuiteRandom) & 16rFF;
            l = l % (K * 2);
            nodes := array [l] of Node;
            for (i := 0; i < l; i++)
                nodes[i] = Node(Key.generate(), "randomnode", 123);
            return ref Rmsg.FindNode(uid, remoteaddr, senderID, targetID, nodes);
        3 =>
            result := random->randomint(random->NotQuiteRandom) & 16rFF;
            l := random->randomint(random->NotQuiteRandom) & 16rFF;
            l = l % (K * 2);
            nodes := array [l] of Node;
            for (i := 0; i < l; i++)
                nodes[i] = Node(Key.generate(), "randomnode", 123);
            l = random->randomint(random->NotQuiteRandom) & 16rFF;
            data := random->randombuf(random->NotQuiteRandom, l);
            return ref Rmsg.FindValue(uid, remoteaddr, senderID, targetID, nodes, list of {ref Dht->StoreItem(data, 0, 0)});
    }

    return nil;
}

# Tests

# Routing table tests

closesttest(count: int, verbose: int)
{
    if (verbose)
        sys->print("trying to get K closest to the random node\n");
    addrandoms(count, 0);
    randomid := Key.generate();
    close := closest(randomid, 0);
    b := Bucket(close, Key.generate(), Key.generate(), daytime->now());
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
    if (verbose)
        sys->print("OK! Closest test passed!\n\n");
}

randomidinrangetest(count: int, verbose: int) 
{
    if (verbose)
        sys->print("checking randomidinbucketrange on %d random ids\n", count);
    b := Bucket(array[0] of Node, Key.generate(), Key.generate(), daytime->now());
    if (verbose)
    {
        sys->print("bucket: \n");
        (ref b).print(0);
    }
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
    if (verbose)
        sys->print("OK! Randomidinrange test passed!\n\n");
}

sequentialtest(verbose: int)
{
    if (verbose)
        sys->print("Adding B*K sequential keys\n");
    for (i := 0; i < B; i++)
    {
        for (j := 0; j <= K; j++)
        {
            idx := local.contacts.findbucket(local.node.id);
            node := ref Node(local.contacts.randomidinbucket(idx),
                "sequential" + string i, 0);
            local.contacts.addcontact(node);
        }
    }
    if (verbose)
    {
        sys->print("OK! Sequential-test passed! Added %d keys\n", countnodes(0));
        sys->print("Number of buckets: %d\n\n", len local.contacts.buckets);
    }
}

filltest(verbose: int)
{
    sequentialtest(0);
    if (verbose)
        sys->print("Trying to fill the whole routing table\n");
    for (i := 0; i < len local.contacts.buckets; i++)
    {
        for (j := 0; j <= K; j++)
        {
            node := ref Node(local.contacts.randomidinbucket(i), "fill test", 0);
            local.contacts.addcontact(node);
        }
    }
    if (verbose)
    {
        sys->print("OK! Total count of contacts: %d\n", countnodes(0));
        sys->print("Number of buckets: %d\n\n", len local.contacts.buckets);
    }
}

# Rmsg/Tmsg tests

randomunpacktest()
{
    sys->print("Trying to unpack random buffer\n");
    l := random->randomint(random->NotQuiteRandom);
    l = l % (MAXRPC * 2);
    if (l < 0)
        l = -l;
    l += 5;
    data := random->randombuf(random->NotQuiteRandom, l);
    data[0] = byte l >> 0;
    data[1] = byte l >> 8;
    data[2] = byte l >> 16;
    data[3] = byte l >> 24;

    data[4] = byte 100;
    {
        sys->print("Parsing Tmsg\n");
        (nil, msg) := Tmsg.unpack(data);
        sys->print("Aw, success! Message read:\n%s\n", msg.text());
    }
    exception e
    {
        "fail:*" =>
            sys->print("Exception catched: %s\n", e);
    }

    data[4] = byte 101;
    {
        sys->print("Parsing Rmsg\n");
        (nil, msg) := Rmsg.unpack(data);
        sys->print("Aw, success! Message read:\n%s\n", msg.text());
    }
    exception e
    {
        "fail:*" =>
            sys->print("Exception catched: %s\n", e);
    }

    sys->print("OK! Random unpack test passed!\n");
    sys->print("\n");
}

randompacktmsgtest()
{
    sys->print("Trying to pack and unpack random Tmsg\n");

    msg := randomtmsg();
    buf := msg.pack();
    buflen := len buf;
    (readlen, newmsg) := Tmsg.unpack(buf);
    newbuf := newmsg.pack();
    if (readlen != buflen || !arreq(buf, newbuf))
    {
        sys->print("Something went wrong!\n");
        sys->print("Buffer is %d bytes, processed %d\n", buflen, readlen);
        sys->print("Message: %s\n", msg.text());
        sys->print("Unpacked message: %s\n", newmsg.text());
        raise "test failed:randompacktmsg";
    }

    sys->print("OK! Random pack test passed!");
    sys->print("\n");
}
randompackrmsgtest()
{
    sys->print("Trying to pack and unpack random Rmsg\n");

    msg := randomrmsg();
    buf := msg.pack();
    buflen := len buf;
    (readlen, newmsg) := Rmsg.unpack(buf);
    newbuf := newmsg.pack();
    if (readlen != buflen || !arreq(buf, newbuf))
    {
        sys->print("Something went wrong!\n");
        sys->print("Buffer is %d bytes, processed %d\n", buflen, readlen);
        sys->print("Message: %s\n", msg.text());
        sys->print("Unpacked message: %s\n", newmsg.text());
        raise "test failed:randompackrmsg";
    }

    sys->print("OK! Random pack test passed!");
    sys->print("\n");
}

starttest()
{
    local = initlocal("", 0);
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
    for (i = 0; i < 100000; i++)
    {
        randompacktmsgtest();
        randompackrmsgtest();
        randomunpacktest();
    }
}

parsenode(args: list of string): ref Node
{
    if (args == nil)
        raise "fail:bad args";

    key := Key.parse(hd args);
    if (key == nil)
        raise "fail:bad key";

    args = tl args;
    if (args == nil)
        raise "fail:bad args";

    addr := hd args;
    args = tl args;
    if (args == nil)
        raise "fail:bad args";

    rtt := int hd args;
    return ref Node(*key, addr, rtt);
}
interactivetest(addr: string)
{
    servers := array [1] of ref Local;
    servers[0] = initlocal(addr, 1);
    local = servers[0];

    stdin := sys->fildes(0);
    print();
    while (1)
    {
        buf := array [100] of byte;
        sys->print("\nDht> ");
        readcnt := sys->read(stdin, buf, 100);
        if (readcnt <= 0)
            raise sys->sprint("fail:stdin read error:%r");
        line := string buf[:readcnt - 1]; # also strip \n

        (argcount, args) := sys->tokenize(line, " ");
        if (argcount == 0)
            continue;

        {
            case (hd args) {
                "help" or "?" =>
                    sys->print("Dht module tester program\n");
                    sys->print("Available commands:\n");
                    sys->print("Multiple server management:\n");
                    sys->print("\tserver <idx>\n");
                    sys->print("\tstartservers <count>\n");
                    sys->print("\tprintservers\n");
                    sys->print("Dht API methods:\n");
                    sys->print("\tfindnode <id>\n");
                    sys->print("\tfindvalue <id>\n");
                    sys->print("\tstore <key> <data>\n");
                    sys->print("\tping <id>\n");
                    sys->print("Manual contacts manipulation:\n");
                    sys->print("\taddcontact <id> <addr> <rtt>\n");
                    sys->print("\tdelcontact <id>\n");
                    sys->print("\tclear\n");
                    sys->print("\tprint\n");
                    sys->print("Tests:\n");
                    sys->print("\tclosesttest <count>\n");
                    sys->print("\trandomidinrangetest <count>\n");
                    sys->print("\tsequentialtest\n");
                    sys->print("\tfilltest\n");
                    sys->print("\trandomunpackmsgtest\n");
                    sys->print("\tpackunpackmsgtest\n");
                    sys->print("Others:\n");
                    sys->print("\tlog\n");
                    sys->print("\texit\n");
                    sys->print("\thelp\n");
                    sys->print("\t?\n");
                "exit" or "quit" or "kill" =>
                    for (i := 1; i < len servers; i++)
                        servers[i].destroy();
                    return;
                "server" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    idx := int hd args;
                    if (idx < 0 || idx >= len servers)
                        raise "fail:bad server index";
                    local = servers[idx];
                "startservers" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    count := int hd args;
                    if (count <= 0)
                        raise "fail:bad server count";
                    newservers := array [count + 1] of ref Local;
                    newservers[0] = servers[0];
                    bootstrap := array [] of {ref servers[0].node};
                    for (i := 1; i < count + 1; i++)
                        newservers[i] = dht->start("udp!127.0.0.1!" + string (12100 + i - 1), bootstrap, Key.generate());
                    servers = newservers;
                "printservers" =>
                    sys->print("Server count: %d\n", len servers);
                    for (i := 0; i < len servers; i++)
                        sys->print("\tServer[%d] = %s\n", i, servers[i].node.id.text());
                    sys->print("Current server: %s\n", local.node.id.text());
                "findnode" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd args);
                    if (key == nil)
                        raise "fail:bad key";
                    node := local.dhtfindnode(*key, nil);
                    if (node != nil)
                        sys->print("Node found! %s\n", node.text());
                    else
                        sys->print("Nothing was found\n");
                "findvalue" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd args);
                    if (key == nil)
                        raise "fail:bad key";
                    items := local.dhtfindvalue(*key);
                    if (items != nil)
                    {
                        sys->print("Something found:\n");
                        for (tail := items; tail != nil; tail = tl tail)
                            sys->print("\t%s\n", string (hd tail).data);
                    }
                    else
                        sys->print("Nothing was found\n");
                "findkclosest" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd args);
                    if (key == nil)
                        raise "fail:bad key";
                    nodes := local.findkclosest(*key);
                    if (len nodes)
                    {
                        sys->print("Found nodes:\n");
                        for (i := 0; i < len nodes; i++)
                            sys->print("%s\n", nodes[i].text());
                    }
                    else
                        sys->print("Nothing was found\n");
                "store" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd args);
                    if (key == nil)
                        raise "fail:bad key";
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad data";
                    data := array of byte hd args;
                    local.dhtstore(*key, data);
                "addcontact" =>
                    args = tl args;
                    node := parsenode(args);
                    local.contacts.addcontact(node);
                    sys->print("%s added!\n", node.text());
                "delcontact" =>
                    if (tl args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd (tl args));
                    if (key == nil)
                        raise "fail:bad key";
                    local.contacts.removecontact(*key);
                    sys->print("Node with key %s removed!\n", (*key).text());
                "ping" =>
                    if (tl args == nil)
                        raise "fail:bad args";
                    key := Key.parse(hd (tl args));
                    if (key == nil)
                        raise "fail:bad key";
                    rtt := local.dhtping(*key);
                    if (rtt > 0)
                        sys->print("Ping success!\nGot answer in %d ms\n", rtt);
                    else
                        sys->print("No answer!\n");
                "print" =>
                    print();
                "clear" =>
                    clean(1);
                "closesttest" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    closesttest(int hd args, 1);
                "randomidinrangetest" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    randomidinrangetest(int hd args, 1);
                "sequentialtest" =>
                    sequentialtest(1);
                "filltest" =>
                    filltest(1);
                "randomunpackmsgtest" =>
                    randomunpacktest();
                "packunpackmsgtest" =>
                    randompackrmsgtest();
                    randompacktmsgtest();
                "log" =>
                    args = tl args;
                    if (args == nil)
                        raise "fail:bad args";
                    fd := sys->create(hd args, Sys->OWRITE, 8r777);
                    local.setlogfd(fd);
                * =>
                    raise "fail:no such command!";
            }
        }
        exception e
        {
            "fail:*" =>
                sys->print("Command failed: %s\n", e[5:]);
            "test failed:*" =>
                sys->print("Test failed: %s\n", e[12:]);
        }
    }
}

init(nil: ref Draw->Context, args: list of string)
{
    # loading modules
    sys = load Sys Sys->PATH;
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

    args = tl args;
    if (args == nil)
        starttest();

    addr := hd args;
    args = tl args;

    if (args != nil && hd args == "-i")
        interactivetest(addr);
    else
        starttest();

    sys->print("cleaning up\n");
    local.destroy();
}
