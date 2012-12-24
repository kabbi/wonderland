implement Dht;

include "sys.m";
    sys: Sys;
include "crc.m";
    crc: Crc;
include "ip.m";
    ip: IP;
    Udphdr, Udphdrlen, IPaddr: import ip;
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
include "sort.m";
    sort: Sort;
include "lists.m";
    lists: Lists;
include "hashtable.m";
    hashtable: Hashtable;
    HashTable: import hashtable;
include "bigkey.m";
    bigkey: Bigkey;
    Key: import bigkey;

include "dht.m";

# different data structure sizes in bytes
LEN: con BIT32SZ;   # string and array length field
COUNT: con BIT32SZ;
OFFSET: con BIT64SZ;
KEY: con BB+LEN;
VALUE: con LEN+BIT32SZ+BIT32SZ;

STORESIZE: con 13;
CALLBACKSIZE: con 13;
HASHSIZE: con 13;
H: con BIT32SZ+BIT8SZ+KEY+LEN+KEY+KEY;  # minimum header length: size[4] type uid[20] remoteaddr[4+] sender[20] target[20]

# minimum packet sizes
hdrlen := array[Tmax] of
{
TPing =>    H,  # no data
RPing =>    H,  # no data

TStore =>   H+KEY+VALUE,      # key[20] value[12+]
RStore =>   H+BIT32SZ,              # result[4]

TFindNode =>    H+KEY,      # no data
RFindNode =>    H+LEN,      # nodes[4+]

TFindValue =>   H+KEY,              # no data
RFindValue =>   H+LEN+LEN,  # nodes[4+] value[4+]
};

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail: init: bad module";
}

init()
{
    sys = load Sys Sys->PATH;
    ip = load IP IP->PATH;
    if (ip == nil)
        badmodule(IP->PATH);
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
    lists = load Lists Lists->PATH;
    if (lists == nil)
        badmodule(Lists->PATH);
    hashtable = load Hashtable Hashtable->PATH;
    if (hashtable == nil)
        badmodule(Hashtable->PATH);
    sort = load Sort Sort->PATH;
    if (sort == nil)
        badmodule(Sort->PATH);
    crc = load Crc Crc->PATH;
    if (crc == nil)
        badmodule(Crc->PATH);
    bigkey->init();
    ip->init();
}

# misc helper functions

abs(a: int): int
{
    if (a < 0) 
        a *= -1;
    return a;
}
dist(k1, k2: Key): Key
{
    r := Key.generate();
    r.data[:] = k1.data[:];
    for (i := 0; i < BB; i++)
        r.data[i] ^= k2.data[i];
    return r;
}
findbyid(x: Key, a: array of ref Node): ref Node
{
    if (a == nil)
        return nil;
    for (i := 0; i < len a; i++)
        if (x.eq(a[i].id))
            return a[i];
    return nil;
}
reaper[T](ch: chan of T, unreaped: int)
{
    for (i := 0; i < unreaped; ++i)
        <- ch;
}
timerreaper(ch: chan of int)
{
    <- ch;
}
toref(a: array of Node): array of ref Node
{
    b := array [len a] of ref Node;
    for (i := 0; i < len a; i++)
        b[i] = ref a[i];
    return b;
}
min(a: int, b: int): int
{
    if (a < b)
        return a;
    return b;
}
crc32(data: array of byte): int
{
    state := crc->init(0, int 16rFFFFFFFF);
    return crc->crc(state, data, len data);
}

# packet serialisation helpers

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

pstoreitem(a: array of byte, o: int, si: ref StoreItem): int
{
    o = parray(a, o, si.data);
    o = p32(a, o, si.lastupdate);
    o = p32(a, o, si.publishtime);
    return o;
}

pvalue(a: array of byte, o: int, l: list of ref StoreItem): int
{
    n := len l;
    o = p32(a, o, n);
    for (tail := l; tail != nil; tail = tl tail)
        o = pstoreitem(a, o, hd tail);
    return o;
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

g32(a: array of byte, o: int): (int, int)
{
    if (o + BIT32SZ > len a)
        raise "fail: g32: malformed packet";
    number := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    return (number, o + BIT32SZ);
}

g64(a: array of byte, o: int): (big, int)
{
    if (o + BIT64SZ > len a)
        raise "fail: g64: malformed packet";
    b0 := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    b1 := (((((int a[o+7] << 8) | int a[o+6]) << 8) | int a[o+5]) << 8) | int a[o+4];
    number := (big b1 << 32) | (big b0 & 16rFFFFFFFF);
    return (number, o + BIT64SZ);
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
    l: int;
    (l, o) = g32(a, o);
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
    key: Key;
    (key, o) = gkey(a, o);
    addr: string;
    (addr, o) = gstring(a, o);
    rtt: int;
    (rtt, o) = g32(a, o);
    return (Node(key, addr, rtt), o);
}

gnodes(a: array of byte, o: int): (array of Node, int)
{
    l: int;
    (l, o) = g32(a, o);
    if (l < 0)
        raise "fail: gnodes: malformed packet";
    nodes := array [l] of Node;
    for (i := 0; i < l; i++)
    {
        node: Node;
        (node, o) = gnode(a, o);
        nodes[i] = node;
    }
    return (nodes, o);
}

gstoreitem(a: array of byte, o: int): (ref StoreItem, int)
{
    data: array of byte;
    (data, o) = garray(a, o);
    lastupdate: int;
    (lastupdate, o) = g32(a, o);
    publishtime: int;
    (publishtime, o) = g32(a, o);
    return (ref StoreItem(data, lastupdate, publishtime), o);
}

gvalue(a: array of byte, o: int): (list of ref StoreItem, int)
{
    l: int;
    (l, o) = g32(a, o);
    if (l < 0)
        raise "fail:gvalue:malformed packet";
    values: list of ref StoreItem;
    for (i := 0; i < l; i++)
    {
        item: ref StoreItem;
        (item, o) = gstoreitem(a, o);
        values = item :: values;
    }
    return (values, o);
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
    ml += len array of byte t.remoteaddr;
    pick m := t {
    Ping =>
        # no dynamic data
    Store =>
        ml += len m.value.data;
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
    o = pstring(d, o, t.remoteaddr);
    o = pkey(d, o, t.senderID);
    o = pkey(d, o, t.targetID);

    pick m := t {
    Ping =>
        # no data
    Store =>
        o = pkey(d, o, m.key);
        o = pstoreitem(d, o, m.value);
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
    (size, o) := g32(f, 0);
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

    o += 1; # for that mptype field
    uid, senderID, targetID: Key;
    remoteaddr: string;
    (uid, o) = gkey(f, o);
    (remoteaddr, o) = gstring(f, o);
    (senderID, o) = gkey(f, o);
    (targetID, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Tmsg.unpack: bad message type";
    TPing =>
        return (o, ref Tmsg.Ping(uid, remoteaddr, senderID, targetID));
    TStore =>
        key: Key;
        (key, o) = gkey(f, o);
        value: ref StoreItem;
        (value, o) = gstoreitem(f, o);
        return (o, ref Tmsg.Store(uid, remoteaddr, senderID, targetID, key, value));
    TFindNode =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindNode(uid, remoteaddr, senderID, targetID, key));
    TFindValue =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindValue(uid, remoteaddr, senderID, targetID, key));
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
    s := sys->sprint("Tmsg.%s(%s,%s,%s->%s,", tmsgname[tagof t], t.uid.text(), t.remoteaddr, t.senderID.text(), t.targetID.text());
    pick m:= t {
    * =>
        return s + ",ILLEGAL)";
    Ping =>
        # no data
        return s + ")";
    Store =>
        return s + sys->sprint("%s,arr[%ud])", m.key.text(), len m.value.data);
    FindNode or FindValue =>
        return s + sys->sprint("%s)", m.key.text());
    }
}

Tmsg.read(fd: ref Sys->FD, msglim: int): ref Tmsg
{
    msg := readbuf(fd, msglim);
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
    mtype := rtag2type[tagof r];
    if(mtype <= 0)
        return 0;
    ml := hdrlen[mtype];
    ml += len array of byte r.remoteaddr;
    pick m := r {
    Ping =>
        # no dynamic data
    Store =>
        # no dynamic data
    FindNode =>
        for (i := 0; i < len m.nodes; i++)
        {
            ml += KEY + BIT32SZ + LEN;
            ml += len (array of byte m.nodes[i].addr);
        }
    FindValue =>
        for (i := 0; i < len m.nodes; i++)
        {
            ml += KEY + BIT32SZ + LEN;
            ml += len (array of byte m.nodes[i].addr);
        }
        for (tail := m.value; tail != nil; tail = tl tail)
        {
            item := hd tail;
            ml += LEN;
            ml += len item.data;
            ml += BIT32SZ;
            ml += BIT32SZ;
        }
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
    d[o++] = byte rtag2type[tagof r];
    o = pkey(d, o, r.uid);
    o = pstring(d, o, r.remoteaddr);
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
        o = pnodes(d, o, m.nodes);
        o = pvalue(d, o, m.value);
    * =>
        raise "fail: Rmsg.pack: bad message type";
    }
    return d;
}

Rmsg.unpack(f: array of byte): (int, ref Rmsg)
{
    if(len f < H)
        raise "fail: Rmsg.unpack: buffer too small";
    (size, o) := g32(f, 0);
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

    o += 1; # for that mptype field
    uid, senderID, targetID: Key;
    remoteaddr: string;
    (uid, o) = gkey(f, o);
    (remoteaddr, o) = gstring(f, o);
    (senderID, o) = gkey(f, o);
    (targetID, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Rmsg.unpack: bad message type";
    RPing =>
        return (o, ref Rmsg.Ping(uid, remoteaddr, senderID, targetID));
    RStore =>
        result: int;
        (result, o) = g32(f, o);
        return (o, ref Rmsg.Store(uid, remoteaddr, senderID, targetID, result));
    RFindNode =>
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        return (o, ref Rmsg.FindNode(uid, remoteaddr, senderID, targetID, nodes));
    RFindValue =>
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        value: list of ref StoreItem;
        (value, o) = gvalue(f, o);
        return (o, ref Rmsg.FindValue(uid, remoteaddr, senderID, targetID, nodes, value));
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
    s := sys->sprint("Rmsg.%s(%s,%s,%s->%s,", Rmsgname[tagof r], r.uid.text(), r.remoteaddr, r.senderID.text(), r.targetID.text());
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
    msg := readbuf(fd, msglim);
    (nil, rmsg) := Rmsg.unpack(msg); 
    return rmsg;
}

readbuf(fd: ref Sys->FD, msglim: int): array of byte
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
    (ml, o) := g32(sbuf, 0);
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
    if (n == nil)
        return "Node(nil)";
    return sys->sprint("Node(%s,%s,%ud)", n.id.text(), n.addr, n.rtt);
}

StoreItem.eq(a, b: ref StoreItem): int
{
    if (len a.data != len b.data)
        return 0;
    for (i := 0; i < len a.data; i++)
        if (a.data[i] != b.data[i])
            return 0;
    return 1;
}

Bucket.isinrange(b: self ref Bucket, id: Key): int
{
    return id.lt(b.maxrange) && !id.lt(b.minrange);
}
Bucket.addnode(b: self ref Bucket, n: ref Node): int
{
    if (len b.nodes >= K)
        return EBucketFull;
    if (b.findnode(n.id) != -1)
        return EAlreadyPresent; # Wouldn't it be better to automaticaly update?
    newnodes := array [len b.nodes + 1] of Node;
    newnodes[:] = b.nodes[:];
    newnodes[len b.nodes] = Node(n.id, n.addr, n.rtt);
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

    sys->print("%s(Bucket [lastaccess=%s]\n", indent, daytime->text(daytime->local(b.lastaccess)));
    sys->print("%s        [minrange=%s]\n", indent, b.minrange.text());
    sys->print("%s        Nodes:\n", indent);
    for (i := 0; i < len b.nodes; i++)
        sys->print("%s             %s:\n", indent, (ref b.nodes[i]).text());
    sys->print("%s        [maxrange=%s])\n", indent, b.maxrange.text());
}

Contacts.addcontact(c: self ref Contacts, n: ref Node)
{
    if (n.id.eq(c.local.node.id))
        return;

    c.local.logevent("addcontact", "Adding contact " + n.text());

    <-c.local.sync;
    bucketInd := c.findbucket(n.id);
    #TODO: Update lastaccess time?
    case c.buckets[bucketInd].addnode(n)
    {
        * =>
            #Success, nothing to do here.
            c.local.logevent("addcontact", "Added successfully");
            c.local.sync <-= 1;
        EBucketFull => 
            c.local.logevent("addcontact", "Bucket full, trying to split");
            #TODO: Substitute to section 2.2 (see l.152 of p2plib)
            if (c.buckets[bucketInd].isinrange(c.local.node.id))
            {
                c.split(bucketInd);
                c.local.sync <-= 1;
                c.addcontact(n);
            }
            else
            {
                node := ref c.buckets[bucketInd].nodes[0];
                msg := ref Tmsg.Ping(Key.generate(), node.addr,
                    c.local.node.id, node.id);
                ch := c.local.sendtmsg(node, msg);
                if (ch != nil)
                    spawn replacefirstnode(c, *n, *node, ch, msg.uid);
                c.local.sync <-= 1;
            }
        EAlreadyPresent =>
            c.local.logevent("addcontact", "Already present, moving to top");
            c.local.sync <-= 1;
            c.removecontact(n.id);
            c.addcontact(n);
    }
}
Contacts.split(c: self ref Contacts, idx: int)
{
    c.local.logevent("split", "Splitting bicket " + string idx);
    #TODO: Update lastaccess time?
    src := c.buckets[idx];
    mid := src.maxrange.subtract(src.maxrange.subtract(src.minrange).halve()); # m = r - ((r - l) / 2)
    l := ref Bucket(array [0] of Node, src.minrange, mid, src.lastaccess);
    r := ref Bucket(array [0] of Node, mid, src.maxrange, src.lastaccess);
    for (i := 0; i < len src.nodes; i++)
    {
        n := ref src.nodes[i];
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
    c.local.logevent("removecontact", "Removing contact " + id.text());
    <-c.local.sync;
    trgbucket := c.buckets[c.findbucket(id)];
    idx := trgbucket.findnode(id);
    if (idx == -1)
        return;
    nodes := array [len trgbucket.nodes - 1] of Node;
    nodes[:] = trgbucket.nodes[:idx];
    nodes[idx:] = trgbucket.nodes[idx+1:];
    trgbucket.nodes = nodes;
    c.buckets[c.findbucket(id)] = trgbucket;
    c.local.sync <-= 1;
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
    c.buckets[idx].lastaccess = daytime->now();
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
    c.local.logevent("findclosenodes", "Findclosenodes called");
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
            buffer := array[len nodes + len newnodes] of Node;
            buffer[:] = nodes[:];
            buffer[len nodes:] = newnodes[:];
            nodes = buffer;
        }
        mod++; 
        sign *= -1;
        i += mod * sign;
            ablemove := (bucketIdx + abs(i) < len c.buckets) || (bucketIdx - abs(i) >= 0);
    }
    c.local.logevent("findclosenodes", "Returned " + string len nodes + " nodes");
    return nodes;
}
Contacts.print(c: self ref Contacts, tabs: int)
{
    indent := string array[tabs] of {* => byte '\t'}; 
    sys->print("%sContacts [key=%s]\n", indent, c.local.node.id.text());
    for (i := 0; i < len c.buckets; i++)
        c.buckets[i].print(tabs + 1);
}

killpid(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}
Local.process(l: self ref Local)
{
    l.processpid = sys->pctl(0, nil);

    # reading incoming packets
    l.conn.dfd = sys->open(l.conn.dir + "/data", Sys->OREAD);
    while (1)
    {
        buffer := array [MAXRPC] of byte;
        bytesread := sys->read(l.conn.dfd, buffer, len buffer);
        l.logevent("process", "New incoming message");

        if (bytesread <= 0)
            raise sys->sprint("fail:Local.process:read error:%r");
        if (bytesread < H)
            continue;

        msgtype := int buffer[4];
        if (msgtype & 1)
            spawn l.processrmsg(buffer);
        else
            spawn l.processtmsg(buffer);
    }
}
Local.processtmsg(l: self ref Local, buf: array of byte)
{
    {
        (nil, msg) := Tmsg.unpack(buf);
        l.logevent("processtmsg", "Incoming Tmsg received");
        l.logevent("processtmsg", "Dump: " + msg.text());
        if (!msg.targetID.eq(l.node.id))
        {
            l.logevent("processtmsg", "The message is discarder, target id error");
            return;
        }

        sender := ref Node(msg.senderID, msg.remoteaddr, 0);

        pick m := msg {
            Ping =>
                answer := ref Rmsg.Ping(m.uid, l.node.addr, l.node.id, m.senderID);
                l.sendrmsg(sender, answer);
            Store =>
                keytext := m.key.text();
                result := SFail;
                if (len m.value.data != 0)
                {
                    items := l.store.find(keytext);
                    if (items != nil)
                    {
			localvalue := lists->find(m.value, items);
                        if (localvalue != nil)
			{
			    (hd localvalue).lastupdate = daytime->now();
			    if ((hd localvalue).publishtime < m.value.publishtime)
		 	        (hd localvalue).publishtime = m.value.publishtime;
                            result = SSuccess;
			}
                        else
                        {
                            items = m.value :: items;
                            l.store.delete(keytext);
                            l.store.insert(keytext, items);
                            result = SSuccess;
                        }
                    }
                    else
                    {
                        l.store.insert(keytext, list of {m.value});
                        result = SSuccess;
                    }
                }
                answer := ref Rmsg.Store(m.uid, l.node.addr, l.node.id, m.senderID, result);
                l.sendrmsg(sender, answer);
            FindNode =>
                nodes := l.contacts.findclosenodes(m.key);
                answer := ref Rmsg.FindNode(m.uid, l.node.addr, l.node.id, m.senderID, nodes);
                l.sendrmsg(sender, answer);
            FindValue =>
                nodes := array [0] of Node;
                value: list of ref StoreItem;
                items := l.store.find(m.key.text());
                if (items == nil)
                    nodes = l.contacts.findclosenodes(m.key);
                else
                    value = items;
                answer := ref Rmsg.FindValue(m.uid, l.node.addr, l.node.id, m.senderID, nodes, value);
                l.sendrmsg(sender, answer);
        }

        # add every incoming node
        l.contacts.addcontact(sender);
    }
#    exception e
#    {
#        "fail:*" =>
#            # nop
#    }
}
Local.processrmsg(l: self ref Local, buf: array of byte)
{
    {
        (nil, msg) := Rmsg.unpack(buf);
        l.logevent("processrmsg", "Incoming Rmsg received.");
        l.logevent("processrmsg", "Dump: " + msg.text());
        if (!msg.targetID.eq(l.node.id))
        {
            l.logevent("processrmsg", "The message is discarder, target id error");
            return;
        }

        ch: chan of ref Rmsg;
        ch = l.callbacks.find(msg.uid.text());
        l.logevent("processrmsg", sys->sprint("Sending message to the callback, success: %d", ch != nil));
        if (ch != nil)
            ch <-= msg;
    }
#    exception e
#    {
#        "fail:*" =>
#            # nop
#    }
}
Local.timer(l: self ref Local)
{
    l.timerpid = sys->pctl(0, nil);

    while (1)
    {
        sys->sleep(1000);
        curtime := daytime->now();

        # refresh buckets
        for (i := 0; i < len l.contacts.buckets; i++)
        {
            bucket := l.contacts.buckets[i];
            if (curtime - bucket.lastaccess > REFRESH_TIME)
            {
                randomkey := l.contacts.randomidinbucket(i);
                l.dhtfindnode(randomkey, nil);
                bucket.lastaccess = curtime;
            }
        }

        # replicate and expire storage
        storage := l.store.all();
        for (rest := storage; rest != nil; rest = tl rest)
        {
            key := *Key.parse((hd rest).key[4:12]); # the key is string like 'key(...)'
            itemlist := (hd rest).val;
            for (tail := itemlist; tail != nil; tail = tl tail)
            {
                item := hd tail;
                # replicate stage
                if (curtime - item.lastupdate > REPLICATE_TIME)
                {
                    item.lastupdate = curtime;
                    storehelper(l, key, item);
                }
                # expire stage
                if (curtime - item.publishtime > EXPIRE_TIME)
                {
                    newitemlist := lists->delete(item, itemlist);
                    l.store.delete((hd rest).key);
                    l.store.insert((hd rest).key, newitemlist);
                }
            }
        }

        # republish our own storage 
        storage = l.ourstore.all();
        for (rest = storage; rest != nil; rest = tl rest)
        {
            key := *Key.parse((hd rest).key[4:12]); # the key is string like 'key(...)'
            itemlist := (hd rest).val;
            for (tail := itemlist; tail != nil; tail = tl tail)
            {
                item := hd tail;
                item.publishtime = daytime->now();
                item.lastupdate = daytime->now();
                storehelper(l, key, item);
            }
        }
    }
}
Local.syncthread(l: self ref Local)
{
    l.syncpid = sys->pctl(0, nil);

    while (1)
    {
        l.sync <-= 1;
        <-l.sync;
    }
}
Local.sendtmsg(l: self ref Local, n: ref Node, msg: ref Tmsg): chan of ref Rmsg
{
    l.logevent("sendtmsg", "Sending message to " + n.text());
    l.logevent("sendtmsg", "Dump: " + msg.text());
    ch := chan of ref Rmsg;

    buf := msg.pack();
    (err, c) := sys->dial(n.addr, "");
    # Here and below, do not throw anything by now
    if (err != 0)
        l.logevent("sendtmsg", sys->sprint("Send error: %r"));
        #raise sys->sprint("fail:sendtmsg:send error:%r");

    l.callbacks.insert(msg.uid.text(), ch);
    sys->write(c.dfd, buf, len buf);
    return ch;
}
Local.sendrmsg(l: self ref Local, n: ref Node, msg: ref Rmsg)
{
    l.logevent("sendrmsg", "Sending message to " + n.text());
    l.logevent("sendrmsg", "Dump: " + msg.text());

    buf := msg.pack();
    (err, c) := sys->dial(n.addr, "");
    if (err != 0)
        l.logevent("sendrsmsg", sys->sprint("Send error: %r"));
        #raise sys->sprint("fail:senrdmsg:send error:%r");
    sys->write(c.dfd, buf, len buf);
}
Local.destroy(l: self ref Local)
{
    # just kill everybody
    l.logevent("destroy", "Quitting...");
    killpid(l.processpid);
    killpid(l.timerpid);
    killpid(l.syncpid);
}

Local.setlogfd(l: self ref Local, fd: ref Sys->FD)
{
    l.logfd = fd;
}
Local.logevent(l: self ref Local, source: string, msg: string)
{
    if (l.logfd != nil)
        sys->fprint(l.logfd, "[%s] %s: %s\n",
            daytime->text(daytime->local(daytime->now())), source, msg);
}

DistComp: adt {
    localid: Key;
    gt: fn(nil: self ref DistComp, n1, n2: ref Node): int;
};
DistComp.gt(dc: self ref DistComp, n1, n2: ref Node): int
{
    return dist(n1.id, dc.localid).gt(dist(n2.id, dc.localid));
}
Local.dhtfindnode(l: self ref Local, id: Key, nodes: array of ref Node): ref Node
# nodes - starting array of nodes:
#    - toref(findclosenodes(id)) - if called regularly
#    - toref(bootstrap array) - if called from bootstrap
{
    l.logevent("dhtfindnode", "Started to search for node " + id.text());
    l.logevent("dhtfindnode", "Starting node array size: " + string len nodes);
    if (nodes == nil)
        nodes = toref(l.contacts.findclosenodes(id));
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", 0));
    asked.insert(l.node.id.text(), ref l.node);
    (node, nil) := dhtfindnode(l, id, nodes, asked, 1, 0);
    return node;
}
Local.dhtfindvalue(l: self ref Local, id: Key): list of ref StoreItem
# Return value: should be list of array of byte?
{
    l.logevent("dhtfindvalue", "Started to search for value " + id.text());
    nodes := toref(l.contacts.findclosenodes(id));
    realnodes := array [len nodes + 1] of ref Node;
    realnodes[:] = nodes[:];
    realnodes[len nodes] = ref l.node;
    l.logevent("dhtfindvalue", "Starting nodes count: " + string len realnodes);
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", 0));
    (nil, items) := dhtfindnode(l, id, realnodes, asked, 0, 1);
    return items;
}
Local.dhtstore(l: self ref Local, key: Key, data: array of byte)
{
    item := ref StoreItem(data, daytime->now(), daytime->now());
    keytext := key.text();
    if (len data != 0)
    {
        items := l.ourstore.find(keytext);
        if (items != nil)
        {
            localvalue := lists->find(item, items);
            if (localvalue != nil)
	    {
	        (hd localvalue).lastupdate = daytime->now();
    	        (hd localvalue).publishtime = daytime->now();
 	    }
            else
            {
                items = item :: items;
                l.ourstore.delete(keytext);
                l.ourstore.insert(keytext, items);
            }
	}
        else
        {
            l.ourstore.insert(keytext, list of {item});
        }
    }
    storehelper(l, key, item);
}
storehelper(l: ref Local, key: Key, value: ref StoreItem)
{
    nodes := l.findkclosest(key);
    for (i := 0; i < len nodes; i++)
        spawn store(l, nodes[i], key, value);
}
Local.findkclosest(l: self ref Local, id: Key): array of ref Node
{
    l.logevent("findkclosest", "Started to search for K closest: " + id.text());
    nodes := toref(l.contacts.findclosenodes(id));
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", 0));
    asked.insert(l.node.id.text(), ref l.node);
    dhtfindnode(l, id, nodes, asked, 0, 0);
    askedlist := asked.all();
    ret := array [len askedlist] of ref Node;

    i := 0;
    for (rest := askedlist; rest != nil; rest = tl rest)
        ret[i++] = (hd rest).val;

    l.logevent("findkclosest", "Returned " + string len ret + " nodes");
    sort->sort(ref DistComp(id), ret);
    return ret[:min(K, len ret)];
}
dhtfindnode(l: ref Local, id: Key, nodes: array of ref Node, asked: ref HashTable[ref Node], search: int, retrievevalue: int): (ref Node, list of ref StoreItem)
# Arguments:
#   ~l: 
#       Link to the local dht-node.
#   ~id:
#       Key corresponing to node or data.
#   ~asked:
#       Set of already asked nodes. Don't need to ask them again.
#   ~search: 
#       Flag. Indicates whether we should return immediately after finding
#             the needed node. Is set in findkclosest.
#   ~retrievevalue: 
#       Flag. Indicates whether we should ask nodes for value with
#             key == ~id. Is set in findvalue.
# Return value: 
#   @ref Node: 
#       A Node with Node.id == ~id, if it was found, nill - otherwise
#   @array of byte:
#       If retrievevalue is set - data stored by the key == ~id
{
    if (!retrievevalue)
    {
        ret := findbyid(id, nodes);
        if (ret != nil && search)
            return (ret, nil);
    }
    sort->sort(ref DistComp(id), nodes);
    listench := chan of ref Rmsg; 

    pending := 0;
    nexttoask := 0;
    while (nexttoask < min(len nodes, ALPHA))
    {
        if (asked.find(nodes[nexttoask].id.text()) != nil)
        {
            ++nexttoask;
            continue;
        }
        asked.insert(nodes[nexttoask].id.text(), nodes[nexttoask]);
        spawn findnode(l, nodes[nexttoask++], id, listench, retrievevalue);
        ++pending;
    }

    while (pending > 0)
    {
        ret: (ref Node, list of ref StoreItem);
        newnodes: array of ref Node;
        msg := <- listench;
        if (msg != nil)
            pick m := msg {
                FindNode =>
                    newnodes = toref(m.nodes);
                    ret = dhtfindnode(l, id, newnodes, asked, search, retrievevalue);
                FindValue =>
                    if (len m.value != 0)
                        return (nil, m.value);
                    newnodes = toref(m.nodes);
                    ret = dhtfindnode(l, id, newnodes, asked, search, retrievevalue);
            }
        --pending;
        (node, nil) := ret;
        if (node != nil && search)
        {
            spawn reaper(listench, pending);
            return ret;
        }
        while (nexttoask < len nodes && asked.find(nodes[nexttoask].id.text()) != nil)
            ++nexttoask;
        if (nexttoask < len nodes)
        { 
            asked.insert(nodes[nexttoask].id.text(), nodes[nexttoask]);
            spawn findnode(l, nodes[nexttoask++], id, listench, retrievevalue);
            ++pending;
        }
    }
    
    return (nil, nil);
}
Local.dhtping(l: self ref Local, id: Key): int
{
    node := l.contacts.getnode(id);
    if (node == nil)
        raise "fail:dhtping:ping node not found";

    l.logevent("dhtping", "Dht ping called with " + id.text());
    msg := ref Tmsg.Ping(Key.generate(), l.node.addr, l.node.id, id);
    ch := l.sendtmsg(node, msg);

    sendtime := sys->millisec();

    killerch := chan of int;
    spawn timer(killerch, 1000);

    result := -1;
    alt {
        answer := <-ch =>
            pick m := answer {
                Ping =>
                    spawn timerreaper(killerch);
                    if (!m.senderID.eq(id))
                    {
                        l.logevent("dhtping", "Received answer from unexpected node");
                        break;
                    }
                    result = sys->millisec() - sendtime;
                * =>
                    spawn timerreaper(killerch);
                    l.logevent("dhtping", "Received answer, but not the desired message format");
            }
        <-killerch =>
            l.logevent("dhtping", "Waiting timeout");
    }
    l.callbacks.delete(msg.uid.text());
    return result;
}

# Callbacks
timer(ch: chan of int, timeout: int)
{
    sys->sleep(timeout);
    ch <-= 1;
}
replacefirstnode(c: ref Contacts, toadd: Node, pingnode: Node, ch: chan of ref Rmsg, uid: Key)
{
    answer: ref Rmsg;
    killerch := chan of int;
    spawn timer(killerch, 1000);
    alt {
        answer = <-ch =>
            pick m := answer {
                Ping =>
                    spawn timerreaper(killerch);
                    if (!m.senderID.eq(pingnode.id))
                    {
                        c.local.logevent("replacefirstnode", "Received answer from unexpected node");
                        break;
                    }
                    c.removecontact(pingnode.id);
                    c.addcontact(ref pingnode);
                * =>
                    spawn timerreaper(killerch);
                    c.local.logevent("replacefirstnode", "Received answer, but not the desired message format");
            }
        <-killerch =>
            c.local.logevent("replacefirstnode", "Answer not received, killing node");
            c.removecontact(pingnode.id);
            c.addcontact(ref toadd);
    }
    c.local.callbacks.delete(uid.text());
}
findnode(l: ref Local, targetnode: ref Node, uid: Key, rch: chan of ref Rmsg, retrievevalue: int)
{
    l.logevent("findnode", "Findnode called, with key " + uid.text());
    msg: ref Tmsg;
    if (retrievevalue)
        msg = ref Tmsg.FindValue(Key.generate(), l.node.addr, l.node.id, targetnode.id, uid);
    else
        msg = ref Tmsg.FindNode(Key.generate(), l.node.addr, l.node.id, targetnode.id, uid);
    ch := l.sendtmsg(targetnode, msg);
    answer: ref Rmsg;
    killerch := chan of int;
    spawn timer(killerch, 2000);
    alt {
        answer = <-ch =>
            if (!answer.senderID.eq(targetnode.id))
            {
                l.logevent("findnode", "Received answer from unexpected node");
                rch <-= nil;
                break;
            }
            pick m := answer {
                FindValue =>
                    spawn timerreaper(killerch);
                    if (!retrievevalue)
                    {
                        l.logevent("findnode", "Received unexpected Rmsg type");
                        rch <-= nil;
                        break;
                    }
                    rch <-= m;
                FindNode =>
                    spawn timerreaper(killerch);
                    if (retrievevalue)
                    {
                        l.logevent("findnode", "Received unexpected Rmsg type");
                        rch <-= nil;
                        break;
                    }
                    rch <-= m;
                * =>
                    spawn timerreaper(killerch);
                    l.logevent("findnode", "Received answer, but not the desired message format");
                    rch <-= nil;
            }
        <-killerch =>
            l.logevent("findnode", "Message wait timeout");
            rch <-= nil;
    }
    l.callbacks.delete(msg.uid.text());
}
store(l: ref Local, where: ref Node, key: Key, value: ref StoreItem)
{
    l.logevent("store", "Store called with key " + key.text());
    l.logevent("store", "Storing to  " + where.text());
    msg := ref Tmsg.Store(Key.generate(), l.node.addr, l.node.id,
               where.id, key, value);
    ch := l.sendtmsg(where, msg);
    answer: ref Rmsg;
    killerch := chan of int;
    spawn timer(killerch, 1000);
    alt {
        answer = <-ch =>
            pick m := answer {
                Store =>
                    spawn timerreaper(killerch);
                    if (!m.senderID.eq(where.id))
                    {
                        l.logevent("store", "Received answer from unexpected node");
                        break;
                    }
                    # check result code
                    case m.result {
                        SSuccess =>
                            l.logevent("store", "Store to " + m.senderID.text() + ": success");
                        SFail =>
                            l.logevent("store", "Store to " + m.senderID.text() + ": fail");
                    } 
                * =>
                    spawn timerreaper(killerch);
                    l.logevent("store", "Received answer, but not the desired message format");
            }
        <-killerch =>
            l.logevent("store", "Message wait timeout");
    }
    l.callbacks.delete(msg.uid.text());
}

start(localaddr: string, bootstrap: array of ref Node, id: Key): ref Local
{
    node := Node(id, localaddr, 0);
    contacts := ref Contacts(array [1] of ref Bucket, nil);
    # construct the first bucket
    contacts.buckets[0] = ref Bucket(array [0] of Node,
        Key(array[BB] of { * => byte 0 }),
        Key(array[BB] of { * => byte 16rFF }),
        daytime->now());

    # try to announce connection
    (err, c) := sys->announce(localaddr);
    if (err != 0)
        return nil;

    ch := chan of ref Rmsg;
    storeitem := list of {ref StoreItem(array [0] of byte, 0, 0)};
    store := hashtable->new(STORESIZE, storeitem);
    localstore := hashtable->new(STORESIZE, storeitem);
    server := ref Local(node, contacts, store, localstore,
        hashtable->new(CALLBACKSIZE, ch), 0, 0, 0, nil, c, chan of int);

    server.contacts.local = server;

    spawn server.process();
    spawn server.timer();
    spawn server.syncthread();

    server.dhtfindnode(id, bootstrap);

    return server;
}
