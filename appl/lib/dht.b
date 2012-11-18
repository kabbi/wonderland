implement Dht;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: Keyring;
include "encoding.m";
    base16: Encoding;
include "security.m";
    random: Random;
include "daytime.m";
    daytime: Daytime;
include "math.m";
    math: Math;
include "bigkey.m";
    bigkey: Bigkey;
    Key: import bigkey;

include "dht.m";

# different data structure sizes in bytes
LEN: con BIT32SZ;   # string and array length field
COUNT: con BIT32SZ;
OFFSET: con BIT64SZ;
KEY: con BB+LEN;
NODE: con KEY+LEN+BIT32SZ;

H: con BIT32SZ+BIT8SZ+KEY+KEY+KEY;  # minimum header length: size[4] type uid[20] sender[20] target[20]

# minimum packet sizes
hdrlen := array[Tmax] of
{
TPing =>    H,  # no data
RPing =>    H,  # no data

TStore =>   H+KEY+LEN+BIT32SZ,      # key[20] data[4+] ask[4]
RStore =>   H+BIT32SZ,              # result[4]

TFindValue =>   H+KEY,              # no data
RFindValue =>   H+BIT32SZ+LEN+LEN,  # result[4] nodes[4+] value[4+]

TFindNode =>    H+KEY,      # no data
RFindNode =>    H+LEN,      # nodes[4+]
};

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail: init: bad module";
}

init()
{
    sys = load Sys Sys->PATH;
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
        badmodule(Keyring->PATH);
    base16 = load Encoding Encoding->BASE16PATH;
    if (base16 == nil)
        badmodule(Encoding->BASE16PATH);
    random = load Random Random->PATH;
    if (random == nil)
        badmodule(Random->PATH);
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
        badmodule(Daytime->PATH);
    math = load Math Math->PATH;
    if (math == nil)
        badmodule(Math->PATH);
    bigkey = load Bigkey Bigkey->PATH;
    if (bigkey == nil)
        badmodule(Bigkey->PATH);
    bigkey->init();
}

abs(a: int): int
{
    if (a < 0) 
        a *= -1;
    return a;
}

pnodes(a: array of byte, o: int, na: array of Node): int
{
    o = p32(a, o, len na);
    for (i:=0; i<len na; i++)
        o = pnode(a, o, na[i]);
    return o;
}

pnode(a: array of byte, o: int, n: Node): int
{
    o = pkey(a, o, n.id);
    o = pstring(a, o, n.addr);
    o = p32(a, o, n.rtt);
    return o;
}

pkey(a: array of byte, o: int, k: Key): int
{
    return parray(a, o, k.data);
}

parray(a: array of byte, o: int, sa: array of byte): int
{
    n := len sa;
    p32(a, o, n);
    a[o+LEN:] = sa;
    return o+LEN+n;
}

pstring(a: array of byte, o: int, s: string): int
{
    sa := array of byte s;
    return parray(a, o, sa);
}

p32(a: array of byte, o: int, v: int): int
{
    a[o] = byte v;
    a[o+1] = byte (v>>8);
    a[o+2] = byte (v>>16);
    a[o+3] = byte (v>>24);
    return o+BIT32SZ;
}

p64(a: array of byte, o: int, b: big): int
{
    i := int b;
    a[o] = byte i;
    a[o+1] = byte (i>>8);
    a[o+2] = byte (i>>16);
    a[o+3] = byte (i>>24);
    i = int (b>>32);
    a[o+4] = byte i;
    a[o+5] = byte (i>>8);
    a[o+6] = byte (i>>16);
    a[o+7] = byte (i>>24);
    return o+BIT64SZ;
}

g32(a: array of byte, o: int): int
{
    if (o + BIT32SZ > len a)
        raise "fail: g32: malformed packet";
    return (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
}

g64(a: array of byte, o: int): big
{
    if (o + BIT64SZ > len a)
        raise "fail: g64: malformed packet";
    b0 := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    b1 := (((((int a[o+7] << 8) | int a[o+6]) << 8) | int a[o+5]) << 8) | int a[o+4];
    return (big b1 << 32) | (big b0 & 16rFFFFFFFF);
}

gstring(a: array of byte, o: int): (string, int)
{
    (str, l) := garray(a, o);
    return (string str, l);
}

garray(a: array of byte, o: int): (array of byte, int)
{
    if(o < 0 || o+LEN > len a)
        raise "fail: garray: malformed packet";
    l := g32(a, o);
    o += LEN;
    e := o+l;
    if(e > len a || l < 0)
        raise "fail: garray: malformed packet";
    return (a[o:e], e);
}

gkey(a: array of byte, o: int): (Key, int)
{
    (data, l) := garray(a, o);
    if (len data != BB)
        raise "fail: gkey: malformed packet";
    return (Key(data), l);
}

gnode(a: array of byte, o: int): (Node, int)
{
    (key, o1) := gkey(a, o);
    (addr, o2) := gstring(a, o1);
    rtt := g32(a, o2);
    return (Node(key, addr, rtt), o2+BIT32SZ);
}

gnodes(a: array of byte, o: int): (array of Node, int)
{
    l := g32(a, o);
    if (l < 0)
        raise "fail: gnodes: malformed packet";
    nodes := array [l] of Node;
    for (i := 0; i < l; i++)
    {
        node: Node;
        (node, o) = gnode(a, o);
        nodes[i] = node;
    }
    return (nodes, -1);
}


# handling TMsgs

ttag2type := array[] of {
tagof Tmsg.Ping => TPing,
tagof Tmsg.Store => TStore,
tagof Tmsg.FindNode => TFindNode,
tagof Tmsg.FindValue => TFindValue
};

Tmsg.mtype(t: self ref Tmsg): int
{
    return ttag2type[tagof t];
}

Tmsg.packedsize(t: self ref Tmsg): int
{
    mtype := ttag2type[tagof t];
    if(mtype <= 0)
        return 0;
    ml := hdrlen[mtype];
    pick m := t {
    Ping =>
        # no dynamic data
    Store =>
        ml += len m.data;
    FindNode or FindValue =>
        # no dynamic data
    }
    return ml;
}

Tmsg.pack(t: self ref Tmsg): array of byte
{
    ds := t.packedsize();
    if(ds <= 0)
        raise "fail: Tmsg.pack: bad packet size";
    d := array [ds] of byte;
    o := 0; # offset
    o = p32(d, o, ds);
    d[o++] = byte ttag2type[tagof t];
    o = pkey(d, o, t.uid);
    o = pkey(d, o, t.senderID);
    o = pkey(d, o, t.targetID);

    pick m := t {
    Ping =>
        # no data
    Store =>
        o = pkey(d, o, m.key);
        o = parray(d, o, m.data);
        o = p32(d, o, m.ask);
    FindNode or FindValue =>
        o = parray(d, o, m.key.data);
    * =>
        raise "fail: Tmsg.pack: bad message type";
    }
    return d;
}

Tmsg.unpack(f: array of byte): (int, ref Tmsg)
{
    if(len f < H)
        raise "fail: Tmsg.unpack: buffer too small";
    size := g32(f, 0);
    if (len f != size)
    {
        if (size < 0)
            raise "fail: Tmsg.unpack: buffer smaller than msg len";
        if(len f < size)
            raise "fail: Tmsg.unpack: buffer too small";
        f = f[0:size];  # trim to exact length
        if(len f < H)
            raise "fail: Tmsg.unpack: msg len read is too small";
    }
    mtype := int f[4];
    if(mtype >= len hdrlen || (mtype&1) != 0 || size < hdrlen[mtype])
        raise "fail: Tmsg.unpack: unknown packet type";

    o := 5; # offset
    uid, senderID, targetID: Key;
    (uid, o) = gkey(f, o);
    (senderID, o) = gkey(f, o);
    (targetID, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Tmsg.unpack: bad message type";
    TPing =>
        return (H, ref Tmsg.Ping(uid, senderID, targetID));
    TStore =>
        key: Key;
        (key, o) = gkey(f, o);
        data: array of byte;
        (data, o) = garray(f, o);
        ask := g32(f, o);
        o += BIT32SZ;
        return (o, ref Tmsg.Store(uid, senderID, targetID, key, data, ask));
    TFindNode =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindNode(uid, senderID, targetID, key));
    TFindValue =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindValue(uid, senderID, targetID, key));
    }
    raise "fail: Tmsg.unpack: malformed packet";
}

tmsgname := array[] of {
tagof Tmsg.Ping => "Ping",
tagof Tmsg.Store => "Store",
tagof Tmsg.FindNode => "FindNode",
tagof Tmsg.FindValue => "FindValue"
};

Tmsg.text(t: self ref Tmsg): string
{
    s := sys->sprint("Tmsg.%s(%s,%s->%s,", tmsgname[tagof t], t.uid.text(), t.senderID.text(), t.targetID.text());
    pick m:= t {
    * =>
        return s + ",ILLEGAL)";
    Ping =>
        # no data
        return s + ")";
    Store =>
        return s + sys->sprint("%s,arr[%ud],%ud)", m.key.text(), len m.data, m.ask);
    FindNode or FindValue =>
        return s + sys->sprint("%s)", m.key.text());
    }
}

Tmsg.read(fd: ref Sys->FD, msglim: int): ref Tmsg
{
    msg := readmsg(fd, msglim);
    (nil, tmsg) := Tmsg.unpack(msg); 
    return tmsg;
}

# handling RMsgs

rtag2type := array[] of {
tagof Rmsg.Ping => RPing,
tagof Rmsg.Store => RStore,
tagof Rmsg.FindNode => RFindNode,
tagof Rmsg.FindValue => RFindValue
};

Rmsg.mtype(r: self ref Rmsg): int
{
    return rtag2type[tagof r];
}

Rmsg.packedsize(r: self ref Rmsg): int
{
    mtype := ttag2type[tagof r];
    if(mtype <= 0)
        return 0;
    ml := hdrlen[mtype];
    pick m := r {
    Ping =>
        # no dynamic data
    Store =>
        ml += BIT32SZ;
    FindNode =>
        ml += (len m.nodes)*NODE;
    FindValue =>
        ml += BIT32SZ+(len m.nodes)*NODE+(len m.value);
    }
    return ml;
}

Rmsg.pack(r: self ref Rmsg): array of byte
{
    ds := r.packedsize();
    if(ds <= 0)
        raise "fail: Rmsg.pack: bad packet size";
    d := array [ds] of byte;
    o := 0; # offset
    o = p32(d, o, ds);
    d[o++] = byte ttag2type[tagof r];
    o = pkey(d, o, r.uid);
    o = pkey(d, o, r.senderID);
    o = pkey(d, o, r.targetID);

    pick m := r {
    Ping =>
        # no data
    Store =>
        o = p32(d, o, m.result);
    FindNode =>
        o = pnodes(d, o, m.nodes);
    FindValue =>
        o = p32(d, o, m.result);
        o = pnodes(d, o, m.nodes);
        o = parray(d, o, m.value);
    * =>
        raise "fail: Rmsg.pack: bad message type";
    }
    return d;
}

Rmsg.unpack(f: array of byte): (int, ref Rmsg)
{
    if(len f < H)
        raise "fail: Rmsg.unpack: buffer too small";
    size := g32(f, 0);
    if(len f != size)
    {
        if(len f < size)
            raise "fail: Rmsg.unpack: buffer smaller than msg len";
        f = f[0:size];  # trim to exact length
        if(len f < H)
            raise "fail: Rmsg.unpack: msg len read is too small";
    }
    mtype := int f[4];
    if(mtype >= len hdrlen || (mtype&1) != 1 || size < hdrlen[mtype])
        raise "fail: Rmsg.unpack: unknown packet type";

    o := 5; # offset
    uid, senderID, targetID: Key;
    (uid, o) = gkey(f, o);
    (senderID, o) = gkey(f, o);
    (targetID, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Rmsg.unpack: bad message type";
    TPing =>
        return (H, ref Rmsg.Ping(uid, senderID, targetID));
    TStore =>
        result := g32(f, o);
        return (o+BIT32SZ, ref Rmsg.Store(uid, senderID, targetID, result));
    TFindNode =>
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        return (o, ref Rmsg.FindNode(uid, senderID, targetID, nodes));
    TFindValue =>
        # implement reading!
        result := g32(f, o);
        o += BIT32SZ;
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        value: array of byte;
        (value, o) = garray(f, o);
        return (o, ref Rmsg.FindValue(uid, senderID, targetID, result, nodes, value));
    }
    raise "fail: Rmsg.unpack: malformed packet";
}

Rmsgname := array[] of {
tagof Rmsg.Ping => "Ping",
tagof Rmsg.Store => "Store",
tagof Rmsg.FindNode => "FindNode",
tagof Rmsg.FindValue => "FindValue"
};

Rmsg.text(r: self ref Rmsg): string
{
    s := sys->sprint("Rmsg.%s(%s,%s->%s,", Rmsgname[tagof r], r.uid.text(), r.senderID.text(), r.targetID.text());
    pick m:= r {
    * =>
        return s + ",ILLEGAL)";
    Ping =>
        # no data
        return s + ")";
    Store =>
        return s + sys->sprint("%ud)", m.result);
    FindNode =>
        nodes: string;
        for (i := 0; i<len m.nodes; i++)
        {
            if (i)
                nodes += ",";
            nodes += (ref m.nodes[i]).text();
        }
        return s + sys->sprint("Nodes[%ud](%s)", len m.nodes, nodes);
    FindValue =>
        nodes: string;
        for (i := 0; i<len m.nodes; i++)
        {
            if (i)
                nodes += ",";
            nodes += (ref m.nodes[i]).text();
        }
        return s + sys->sprint("Nodes[%ud](%s),arr[%ud])", len m.nodes, nodes, len m.value);
    }
}

Rmsg.read(fd: ref Sys->FD, msglim: int): ref Rmsg
{
    msg := readmsg(fd, msglim);
    (nil, rmsg) := Rmsg.unpack(msg); 
    return rmsg;
}

readmsg(fd: ref Sys->FD, msglim: int): array of byte
{
    if(msglim <= 0)
        msglim = MAXRPC;
    sbuf := array [BIT32SZ] of byte;
    if((n := sys->readn(fd, sbuf, BIT32SZ)) != BIT32SZ)
    {
        if(n == 0)
            raise "fail: readmsg: read failed, got 0 bytes";
        raise sys->sprint("fail: readmsg: read failed: %r");
    }
    ml := g32(sbuf, 0);
    if(ml <= BIT32SZ)
        raise "fail: readmsg: invalid message size";
    if(ml > msglim)
        raise "fail: readmsg: message is longer that agreed";
    buf := array [ml] of byte;
    buf[:] = sbuf;
    if((n = sys->readn(fd, buf[BIT32SZ:], ml-BIT32SZ)) != ml-BIT32SZ)
    {
        if(n == 0)
            raise "fail: readmsg: message truncated";
        raise sys->sprint("fail: readmsg: read failed: %r");
    }
    return buf;
}

# What is that?
istmsg(f: array of byte): int
{
    if(len f < H)
        raise "fail: istmsg: buffer too small to be a message";
    return (int f[BIT32SZ] & 1) == 0;
}

Node.text(n: self ref Node): string
{
    return sys->sprint("Node(%s,%s,%ud)", n.id.text(), n.addr, n.rtt);
}

Bucket.isinrange(b: self ref Bucket, id: Key): int
{
    return id.lt(b.maxrange) && !id.lt(b.minrange);
}
Bucket.addnode(b: self ref Bucket, n: Node): int
{
    if (len b.nodes >= K)
        return EBucketFull;
    if (b.findnode(n.id) != -1)
        return EAlreadyPresent; # Wouldn't it be better to automaticaly update?
    newnodes := array [len b.nodes + 1] of Node;
    newnodes[:] = b.nodes[:];
    newnodes[len b.nodes] = n;
    b.nodes = newnodes;
    return 0;
}
Bucket.getnodes(b: self ref Bucket, size: int): array of Node
{
    # return 'size' last nodes
    if (len b.nodes >= size)
        return b.nodes[len b.nodes - size:];
    else
	return b.nodes;
}
Bucket.findnode(b: self ref Bucket, id: Key): int
{
    for (i := 0; i < len b.nodes; i++)
        if (b.nodes[i].id.eq(id))
            return i;
    # not found
    return -1;
}
Bucket.print(b: self ref Bucket, tabs: int)
{
    indent := string array[tabs] of {* => byte '\t'}; 

    sys->print("%s(Bucket [lastaccess=%s]\n", indent, daytime->text(ref b.lastaccess));
    sys->print("%s        [minrange=%s]\n", indent, b.minrange.text());
    sys->print("%s        Nodes:\n", indent);
    for (i := 0; i < len b.nodes; i++)
        sys->print("%s             %s:\n", indent, (ref b.nodes[i]).text());
    sys->print("%s        [maxrange=%s])\n", indent, b.maxrange.text());
}

Contacts.addcontact(c: self ref Contacts, n: ref Node)
{
    if (n.id.eq(c.localid))
        return;

    bucketInd := c.findbucket(n.id);
    #TODO: Update lastaccess time?
    case c.buckets[bucketInd].addnode(*n)
    {
        * =>
            #Success, nothing to do here.
        EBucketFull => 
            #TODO: Substitute to section 2.2 (see l.152 of p2plib)
            if (c.buckets[bucketInd].isinrange(c.localid))
            {
                c.split(bucketInd);
                c.addcontact(n);
            }
        EAlreadyPresent =>
            c.removecontact(n.id);
            c.addcontact(n);
    }
}
Contacts.split(c: self ref Contacts, idx: int)
{
    #TODO: Update lastaccess time?
    src := c.buckets[idx];
    mid := src.maxrange.subtract(src.maxrange.subtract(src.minrange).halve()); # m = r - ((r - l) / 2)
    l := ref Bucket(array [0] of Node, src.minrange, mid, src.lastaccess);
    r := ref Bucket(array [0] of Node, mid, src.maxrange, src.lastaccess);
    for (i := 0; i < len src.nodes; i++)
    {
        n := src.nodes[i];
        if (l.isinrange(n.id))
            l.addnode(n);
        else
            r.addnode(n);
    }
    newbuckets := array [len c.buckets + 1] of ref Bucket;
    newbuckets[:] = c.buckets[:idx];
    newbuckets[idx] = l;
    newbuckets[idx + 1] = r;
    if (idx + 2 < len newbuckets)
        newbuckets[idx + 2:] = c.buckets[idx + 1:];
    c.buckets = newbuckets;
}
Contacts.removecontact(c: self ref Contacts, id: Key)
{
    trgbucket := c.buckets[c.findbucket(id)];
    idx := trgbucket.findnode(id);
    if (idx == -1)
        return;
    nodes := array [len trgbucket.nodes - 1] of Node;
    nodes[:] = trgbucket.nodes[:idx];
    nodes[idx:] = trgbucket.nodes[idx+1:];
    trgbucket.nodes = nodes;
    c.buckets[c.findbucket(id)] = trgbucket;
}
Contacts.findbucket(c: self ref Contacts, id: Key): int
{
    for (i := 0; i < len c.buckets; i++)
        if (c.buckets[i].isinrange(id))
            return i;
    # not found
    return -1;
}
Contacts.randomidinbucket(c: self ref Contacts, idx: int): Key
{
    h := c.buckets[idx].maxrange.data;
    l := c.buckets[idx].minrange.data;
    (ltmax, gtmin) := (0, 0);
    top, bot, cur: byte;

    ret := Key(array[BB] of byte);
    for (i := 0; i < BB; i++)
    {
        (top, bot) = (byte 16rFF, byte 0);
        if (!gtmin)
           bot = l[i];
        if (!ltmax)
           top = h[i];
        cur = byte ((abs(random->randomint(random->NotQuiteRandom)) % (int top - int bot + 1)) + int bot);
        ret.data[i] = cur;
        if (cur < top)
            ltmax = 1;
        if (cur > bot)
            gtmin = 1;
    }
    if (!ltmax)
        return ret.dec();
    return ret;
}

Contacts.touch(c: self ref Contacts, idx: int)
{
    c.buckets[idx].lastaccess = *daytime->local(daytime->now());
}
Contacts.getnode(c: self ref Contacts, id: Key): ref Node
{
    idx := c.findbucket(id);
    if (idx == -1)
        return nil;
    nodeIdx := c.buckets[idx].findnode(id);
    if (nodeIdx == -1)
        return nil;
    return ref c.buckets[idx].nodes[nodeIdx];
}
Contacts.findclosenodes(c: self ref Contacts, id: Key): array of Node
{
    bucketIdx := c.findbucket(id);
    nodes := c.buckets[bucketIdx].getnodes(K);
    (i, mod, sign) := (1, 1, 1);
    ablemove := (bucketIdx + abs(i) < len c.buckets) || (bucketIdx - abs(i) >= 0);
    buffer, newnodes: array of Node;
    while (len nodes < K && ablemove) 
    {
        if ((bucketIdx + i < len c.buckets) && (bucketIdx + i >= 0))
        {
            newnodes = c.buckets[bucketIdx + i].getnodes(K - len nodes);
            buffer := array[len nodes + len buffer] of Node;
            buffer[:] = nodes[:];
            buffer[len nodes:] = newnodes[:];
            nodes = buffer;
        }
        mod++; 
        sign *= -1;
        i += mod * sign;
            ablemove := (bucketIdx + abs(i) < len c.buckets) || (bucketIdx - abs(i) >= 0);
    }
    return nodes;
}
Contacts.print(c: self ref Contacts, tabs: int)
{
    indent := string array[tabs] of {* => byte '\t'}; 
    sys->print("%sContacts [key=%s]\n", indent, c.localid.text());
    for (i := 0; i < len c.buckets; i++)
        c.buckets[i].print(tabs + 1);
}

killpid(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}
Local.process(l: self ref Local, conn: Sys->Connection)
{
    l.processpid = sys->pctl(0, nil);

    # reading incoming packets
    buffer := array [60000] of byte;
    conn.dfd = sys->open(conn.dir + "/data", Sys->OREAD);
    while (1)
    {
        bytesread := sys->read(conn.dfd, buffer, len buffer);
        # actually processing data here...
    }
}
Local.timer(l: self ref Local)
{
    l.timerpid = sys->pctl(0, nil);

    while (1)
    {
        # do something really usefull here...
        sys->sleep(1000);
    }
}
Local.destroy(l: self ref Local)
{
    # just kill everybody
    #killpid(l.processpid);
    #killpid(l.timerpid);
}


start(localaddr: string, bootstrap: ref Node, id: Key): ref Local
{
    node := Node(id, localaddr, 0);
    contacts := ref Contacts(array [1] of ref Bucket, id);
    # construct the first bucket
    contacts.buckets[0] = ref Bucket(array [0] of Node,
        Key(array[BB] of { * => byte 0 }),
        Key(array[BB] of { * => byte 16rFF }),
        *daytime->local(daytime->now()));

    store: list of (Key, array of byte, Daytime->Tm);
    server := ref Local(node, contacts, store, 0, 0);

    # try to announce connection
    #(err, c) := sys->announce(localaddr);
    #if (err != 0)
    #    return nil;

    #spawn server.process(c);
    #spawn server.timer();

    return server;
}
