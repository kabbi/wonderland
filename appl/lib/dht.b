implement Dht;

include "sys.m";
    sys: Sys;
include "crc.m";
    crc: Crc;
include "ip.m";
    ip: IP;
    Udphdr, Udp4hdrlen, IPaddr: import ip;
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
H: con BIT32SZ+BIT8SZ+KEY+KEY+KEY;  # minimum header length: size[4] type uid[20] sender[20] target[20]
TH: con LEN+LEN+LEN+KEY; # Tmsg added header size: senderpubaddr senderprvadd sendersrvaddr sendersrvid

# minimum packet sizes
hdrlen := array[Tmax] of
{
TPing =>             H+TH,                # no data
RPing =>             H,                   # no data

TStore =>            H+KEY+VALUE+TH,      # key[20] value[12+]
RStore =>            H+BIT32SZ,           # result[4]

TFindNode =>         H+KEY+TH,            # no data
RFindNode =>         H+LEN,               # nodes[4+]

TFindValue =>        H+KEY+TH,            # no data
RFindValue =>        H+LEN+LEN,           # nodes[4+] value[4+]

TAskRandezvous =>    H+LEN+KEY+TH,        # address + key
RAskRandezvous =>    H+BIT32SZ,           # result

TInvitation =>       H+LEN+LEN+KEY+TH,    # {pub, prv}address[4+] + key[20]
RInvitation =>       H+BIT32SZ,           # result

TObserve =>          H+TH,                # no data
RObserve =>          H+BIT32SZ,           # result[4]

TUser =>             H+TH+LEN,            # data[4+]
RUser =>             H+LEN,               # data[4+]
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

#
# [[/netdir/]proto!]addr!port
#
dialparse(addr: string): (IPaddr, int)
{
    (nil, parts) := sys->tokenize(addr, "!");
    if (parts == nil || len parts != 3)
        raise "fail:dialparse:bad address";
    parts = tl parts; # skip proto
    (err, ipaddr) := IPaddr.parse(hd parts);
    if (err < 0)
        raise "fail:dialparse:bad ip part";
    parts = tl parts;
    return (ipaddr, int hd parts);
}
ispublic(n: ref Node): int
{
    # GLOBAL TRAVERSE TODO: "Openness" of the node problem. Should be discovered by the net.
    return n.pubaddr == n.prvaddr;
}
swap(a, b: ref Node)
{
    t := a;
    a = b;
    b = t;
}
randomshuffle(a: array of ref Node)
{
    for (i := 0; i < len a; ++i)
    {
        dist := abs(random->randomint(random->NotQuiteRandom) % (len a - i));
        swap(a[i], a[i+dist]);
    }
}
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
    o = pstring(a, o, n.prvaddr);
    o = pstring(a, o, n.pubaddr);
    o = pstring(a, o, n.srvaddr);
    o = pkey(a, o, n.srvid);
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
    key, srvid: Key;
    prvaddr, pubaddr, srvaddr: string;
    (key, o) = gkey(a, o);
    (prvaddr, o) = gstring(a, o);
    (pubaddr, o) = gstring(a, o);
    (srvaddr, o) = gstring(a, o);
    (srvid, o) = gkey(a, o);
    return (Node(key, prvaddr, pubaddr, srvaddr, srvid), o);
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
tagof Tmsg.FindValue => TFindValue,
tagof Tmsg.AskRandezvous => TAskRandezvous,
tagof Tmsg.Invitation => TInvitation,
tagof Tmsg.Observe => TObserve,
tagof Tmsg.User => TUser
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
    ml += len array of byte t.sender.prvaddr;
    ml += len array of byte t.sender.pubaddr;
    ml += len array of byte t.sender.srvaddr;
    pick m := t {
    Ping =>
        # no dynamic data
    Store =>
        ml += len m.value.data;
    FindNode or FindValue =>
        # no dynamic data
    AskRandezvous =>
        ml += len array of byte m.addr;
    Invitation =>
        ml += len array of byte m.oppprvaddr +
              len array of byte m.opppubaddr;
    Observe =>
        # no dynamic data
    User =>
        ml += len m.data;
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
    o = pnode(d, o, t.sender);
    o = pkey(d, o, t.targetid);

    pick m := t {
    Ping =>
        # no data
    Store =>
        o = pkey(d, o, m.key);
        o = pstoreitem(d, o, m.value);
    FindNode or FindValue =>
        o = parray(d, o, m.key.data);
    AskRandezvous =>
        o = pkey(d, o, m.oppid);
        o = pstring(d, o, m.addr);
    Invitation =>
        o = pstring(d, o, m.oppprvaddr);
        o = pstring(d, o, m.opppubaddr);
        o = pkey(d, o, m.oppid);
    Observe =>
        # no data 
    User =>
        o = parray(d, o, m.data);
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
    uid, targetid: Key;
    sender: Node;
    (uid, o) = gkey(f, o);
    (sender, o) = gnode(f, o);
    (targetid, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Tmsg.unpack: bad message type";
    TPing =>
        return (o, ref Tmsg.Ping(uid, sender, targetid));
    TStore =>
        key: Key;
        (key, o) = gkey(f, o);
        value: ref StoreItem;
        (value, o) = gstoreitem(f, o);
        return (o, ref Tmsg.Store(uid, sender, targetid, key, value));
    TFindNode =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindNode(uid, sender, targetid, key));
    TFindValue =>
        key: Key;
        (key, o) = gkey(f, o);
        return (o, ref Tmsg.FindValue(uid, sender, targetid, key));
    TAskRandezvous =>
        addr: string;
        id: Key;
        (id, o) = gkey(f, o);
        (addr, o) = gstring(f, o);
        return (o, ref Tmsg.AskRandezvous(uid, sender, targetid, id, addr));
    TInvitation =>
        oppprvaddr, opppubaddr: string;
        oppid: Key;
        (oppprvaddr, o) = gstring(f, o);
        (opppubaddr, o) = gstring(f, o);
        (oppid, o) = gkey(f, o);
        return (o, ref Tmsg.Invitation(uid, sender, targetid, oppprvaddr, opppubaddr, oppid));
    TObserve =>
        return (o, ref Tmsg.Observe(uid, sender, targetid));
    TUser =>
        data: array of byte;
        (data, o) = garray(f, o);
        return (o, ref Tmsg.User(uid, sender, targetid, data));
    }
    raise "fail: Tmsg.unpack: malformed packet";
}

tmsgname := array[] of {
tagof Tmsg.Ping => "Ping",
tagof Tmsg.Store => "Store",
tagof Tmsg.FindNode => "FindNode",
tagof Tmsg.FindValue => "FindValue",
tagof Tmsg.AskRandezvous => "AskRandezvous",
tagof Tmsg.Invitation => "Invitation",
tagof Tmsg.Observe => "Observe",
tagof Tmsg.User => "User"
};

Tmsg.text(t: self ref Tmsg): string
{
    s := sys->sprint("Tmsg.%s(%s,[%s/%s],%s->%s,", tmsgname[tagof t], t.uid.text(), 
                                  t.sender.prvaddr, t.sender.pubaddr, 
                                  t.sender.id.text(), t.targetid.text());
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
    AskRandezvous =>
        return s + sys->sprint("(OppAddr, ID) = (%s, %s))", m.addr, m.oppid.text());
    Invitation =>
        return s + sys->sprint("%s)", m.oppid.text());
    Observe =>
        # no data
        return s + ")";
    User =>
        return s + sys->sprint("data[%ud])", len m.data);
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
tagof Rmsg.FindValue => RFindValue,
tagof Rmsg.AskRandezvous => RAskRandezvous,
tagof Rmsg.Invitation => RInvitation,
tagof Rmsg.Observe => RObserve,
tagof Rmsg.User => RUser
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
    pick m := r {
    Ping =>
        # no dynamic data
    Store =>
        # no dynamic data
    FindNode =>
        for (i := 0; i < len m.nodes; i++)
        {
            ml += KEY + LEN + LEN + LEN + KEY;
            ml += len (array of byte m.nodes[i].prvaddr);
            ml += len (array of byte m.nodes[i].pubaddr);
            ml += len (array of byte m.nodes[i].srvaddr);
        }
    FindValue =>
        for (i := 0; i < len m.nodes; i++)
        {
            ml += KEY + LEN + LEN + LEN + KEY;
            ml += len (array of byte m.nodes[i].prvaddr);
            ml += len (array of byte m.nodes[i].pubaddr);
            ml += len (array of byte m.nodes[i].srvaddr);
        }
        for (tail := m.value; tail != nil; tail = tl tail)
        {
            item := hd tail;
            ml += LEN;
            ml += len item.data;
            ml += BIT32SZ;
            ml += BIT32SZ;
        }
    AskRandezvous =>
        # no dynamic data 
    Invitation =>
        # no dynamic data
    Observe =>
        ml += len array of byte m.observedaddr;
    User =>
        ml += len m.data;
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
    o = pkey(d, o, r.senderid);
    o = pkey(d, o, r.targetid);

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
    AskRandezvous =>
        o = p32(d, o, m.result);
    Invitation =>
        o = p32(d, o, m.result);
    Observe =>
        o = pstring(d, o, m.observedaddr);
    User =>
        o = parray(d, o, m.data);
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
    (uid, o) = gkey(f, o);
    (senderID, o) = gkey(f, o);
    (targetID, o) = gkey(f, o);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        raise "fail: Rmsg.unpack: bad message type";
    RPing =>
        return (o, ref Rmsg.Ping(uid, senderID, targetID));
    RStore =>
        result: int;
        (result, o) = g32(f, o);
        return (o, ref Rmsg.Store(uid, senderID, targetID, result));
    RFindNode =>
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        return (o, ref Rmsg.FindNode(uid, senderID, targetID, nodes));
    RFindValue =>
        nodes: array of Node;
        (nodes, o) = gnodes(f, o);
        value: list of ref StoreItem;
        (value, o) = gvalue(f, o);
        return (o, ref Rmsg.FindValue(uid, senderID, targetID, nodes, value));
    RAskRandezvous =>
        result: int;
        (result, o) = g32(f, o);
        return (o, ref Rmsg.AskRandezvous(uid, senderID, targetID, result));
    RInvitation =>
        result: int;
        (result, o) = g32(f, o);
        return (o, ref Rmsg.Invitation(uid, senderID, targetID, result));
    RObserve =>
        observedaddr: string;
        (observedaddr, o) = gstring(f, o);
        return (o, ref Rmsg.Observe(uid, senderID, targetID, observedaddr));
    RUser =>
        data: array of byte;
        (data, o) = garray(f, o);
        return (o, ref Rmsg.User(uid, senderID, targetID, data));
    }
    raise "fail: Rmsg.unpack: malformed packet";
}

Rmsgname := array[] of {
tagof Rmsg.Ping => "Ping",
tagof Rmsg.Store => "Store",
tagof Rmsg.FindNode => "FindNode",
tagof Rmsg.FindValue => "FindValue",
tagof Rmsg.AskRandezvous => "AskRandezvous",
tagof Rmsg.Invitation => "Invitation",
tagof Rmsg.Observe => "Observe",
tagof Rmsg.User => "User"
};

Rmsg.text(r: self ref Rmsg): string
{
    s := sys->sprint("Rmsg.%s(%s,%s->%s,", Rmsgname[tagof r], r.uid.text(), r.senderid.text(), r.targetid.text());
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
    AskRandezvous =>
        return s + sys->sprint("%ud)", m.result);
    Invitation =>
        return s + sys->sprint("%ud)", m.result);
    Observe =>
        return s + sys->sprint("%s)", m.observedaddr);
    User =>
        return s + sys->sprint("data[%ud])", len m.data);
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

Node.text(n: self ref Node): string
{
    if (n == nil)
        return "Node(nil)";
    return sys->sprint("Node(%s,[%s/%s],Srv:%s)", n.id.text(), 
                                 n.prvaddr, n.pubaddr, n.srvaddr);
}
Node.eq(n1: ref Node, n2: ref Node): int
{
    return n1.id.eq(n2.id);
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
    #TODO: Rewrite with lists!
    if (len b.nodes >= K)
        return EBucketFull;
    if (b.findnode(n.id) != nil)
        return EAlreadyPresent; 
    b.nodes = n :: lists->delete(n, b.nodes);
    return 0;
}
Bucket.getnodes(b: self ref Bucket, size: int): array of Node
{
    # return 'size' first nodes
    tail := b.nodes;
    result := array [min(size, len b.nodes)] of Node;
    for (i := 0; i < len result; i++)
    {
        result[i] = *(hd tail);
        tail = tl tail;
    }
    return result;
}
Bucket.removenode(b: self ref Bucket, id: Key)
{
    dummynode := ref Node(id, "", "", "", id);
    b.nodes = lists->delete(dummynode, b.nodes);
}
Bucket.findnode(b: self ref Bucket, id: Key): ref Node
{
    dummynode := ref Node(id, "", "", "", id);
    tail := lists->find(dummynode, b.nodes);
    if (tail != nil)
        return hd tail;
    return nil;
}
Bucket.text(b: self ref Bucket, tabs: int): string
{
    indent := string array[tabs] of {* => byte '\t'}; 

    s := sys->sprint("%s(Bucket [lastaccess=%s]\n", indent, daytime->text(daytime->local(b.lastaccess)));
    s += sys->sprint("%s        [minrange=%s]\n", indent, b.minrange.text());
    s += sys->sprint("%s        Nodes:\n", indent);
    for (tail := b.nodes; tail != nil; tail = tl tail)
        s += sys->sprint("%s             %s:\n", indent, (hd tail).text());
    s += sys->sprint("%s        [maxrange=%s])\n", indent, b.maxrange.text());
    return s;
}

Contacts.addcontact(c: self ref Contacts, n: ref Node)
{
    if (n.id.eq(c.local.node.id))
        return;

    c.local.logevent("addcontact", "Adding contact " + n.text());

    bucketInd := c.findbucket(n.id);
    case c.buckets[bucketInd].addnode(n)
    {
        * =>
            #Success, nothing to do here.
            c.local.logevent("addcontact", "Added successfully");
        EBucketFull => 
            c.local.logevent("addcontact", "Bucket full, trying to split");
            #TODO: Substitute to section 2.2 (see l.152 of p2plib)
            if (c.buckets[bucketInd].isinrange(c.local.node.id))
            {
                c.split(bucketInd);
                c.addcontact(n);
            }
            else
            {
                node := hd c.buckets[bucketInd].nodes;
                msg := ref Tmsg.Ping(Key.generate(), c.local.node, node.id);
                spawn replacefirstnode(c, n, node, msg);
            }
        EAlreadyPresent =>
            c.local.logevent("addcontact", "Already present, moving to top");
            c.removecontact(n.id);
            c.addcontact(n);
    }
}
Contacts.split(c: self ref Contacts, idx: int)
{
    c.local.logevent("split", "Splitting bucket " + string idx);
    src := c.buckets[idx];
    mid := src.maxrange.subtract(src.maxrange.subtract(src.minrange).halve()); # m = r - ((r - l) / 2)
    l := ref Bucket(nil, src.minrange, mid, src.lastaccess);
    r := ref Bucket(nil, mid, src.maxrange, src.lastaccess);
    for (tail := src.nodes; tail != nil; tail = tl tail)
    {
        n := hd tail;
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
    trgbucket := c.buckets[c.findbucket(id)];
    trgbucket.removenode(id);
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
    return c.buckets[idx].findnode(id);
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
Contacts.getpublicnodes(c: self ref Contacts): array of ref Node
{
    #TODO: Keep track of pulic nodes, do not go through whole list
    b := c.buckets; #Damn, it still allows races! #$%!&!, Damned refs!
    count := 0;
    for (i := 0; i < len b; ++i)
        for (tail := b[i].nodes; tail != nil; tail = tl tail)
            if (ispublic(hd tail))
                ++count;
    l := array [count] of ref Node;
    count = 0;
    for (i = 0; i < len b; ++i)
        for (tail = b[i].nodes; tail != nil; tail = tl tail)
            if (ispublic(hd tail))
                l[count++] = hd tail;
    return l;
}
Contacts.text(c: self ref Contacts, tabs: int): string
{
    indent := string array[tabs] of {* => byte '\t'}; 
    s := sys->sprint("%sContacts [key=%s]\n", indent, c.local.node.id.text());
    for (i := 0; i < len c.buckets; i++)
        s += c.buckets[i].text(tabs + 1);
    return s;
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
    # turn on headers mode
    sys->fprint(l.conn.cfd, "headers4");

    # reading incoming packets
    l.conn.dfd = sys->open(l.conn.dir + "/data", Sys->ORDWR);
    while (1)
    {
        buffer := array [MAXRPC + Udp4hdrlen] of byte;
        bytesread := sys->read(l.conn.dfd, buffer, len buffer);
        l.logevent("process", "New incoming message");

        hdr := Udphdr.unpack(buffer[:Udp4hdrlen], Udp4hdrlen);
        if (hdr == nil)
            raise "fail:Local.process:headers parsing error";
        raddr := "udp!" + hdr.raddr.text() + "!" + string hdr.rport;
        l.logevent("process", "remote addr: " + raddr);
        buffer = buffer[Udp4hdrlen:];

        if (bytesread <= 0)
            raise sys->sprint("fail:Local.process:read error:%r");
        if (bytesread < H + Udp4hdrlen)
        {
            l.stats.processerrors++;
            l.logevent("process", "Incoming packet too short, ignoring");
            continue;
        }

        msgtype := int buffer[4];
        l.stats.recvmsgsbytype[msgtype - 100]++;
        if (msgtype & 1)
            spawn l.processrmsg(buffer);
        else
            spawn l.processtmsg(buffer, raddr);
    }
}
Local.processtmsg(l: self ref Local, buf: array of byte, raddr: string)
{
    {
        (nil, msg) := Tmsg.unpack(buf);
        l.stats.recvdtmsgs++;
        l.logevent("processtmsg", "Incoming Tmsg received");
        l.logevent("processtmsg", "Dump: " + msg.text());
        if (!msg.targetid.eq(l.node.id))
        {
            l.logevent("processtmsg", "The message is discarder, target id error");
            return;
        }

        sender := ref msg.sender;
        shouldadd := 1;

        answer: ref Rmsg;
        pick m := msg {
            Ping =>
                answer = ref Rmsg.Ping(m.uid, l.node.id, sender.id);
            Store =>
                result := SFail;
                # insert or update in our node's storage
                if (len m.value.data != 0)
                {
                    replacement := ref StoreItem(m.value.data, m.value.lastupdate, m.value.publishtime);
                    l.storech <-= (m.key.text(), m.value, replacement, l.store);
                    result = SSuccess;
                }
                answer = ref Rmsg.Store(m.uid, l.node.id, sender.id, result);
            FindNode =>
                if (m.key.eq(l.node.id))
                {
                    l.logevent("processtmsg", "Ignoring FindValue on self id");
                    break;
                }
                nodes := l.contacts.findclosenodes(m.key);
                answer = ref Rmsg.FindNode(m.uid, l.node.id, sender.id, nodes);
            FindValue =>
                nodes := array [0] of Node;
                value: list of ref StoreItem;
                items := l.store.find(m.key.text());
                if ((items == nil || len items == 0) && !m.key.eq(l.node.id))
                    nodes = l.contacts.findclosenodes(m.key);
                else
                    value = items;
                answer = ref Rmsg.FindValue(m.uid, l.node.id, sender.id, nodes, value);
            AskRandezvous =>
                spawn l.processrandezvousquery(m, sender);
            Invitation => 
                traverser := ref Rmsg.Ping(m.uid, l.node.id, m.oppid);
                l.sendrmsg(m.oppprvaddr, m.opppubaddr, traverser);
                answer = ref Rmsg.Invitation(m.uid, l.node.id, sender.id, RSuccess);
            Observe =>
                shouldadd = 0;
                sender.pubaddr = raddr;
                answer = ref Rmsg.Observe(m.uid, l.node.id, sender.id, raddr);
            User =>
                if (l.usermsghandler != nil)
                    l.usermsghandler <-= m;
                shouldadd = 0;
        }

        # add every incoming node except for observed
        if (shouldadd)
            l.contactsch <-= (QAddContact, sender);
        if (answer != nil)
            l.sendrmsg(sender.prvaddr, sender.pubaddr, answer);
    }
    exception e
    {
        "fail:*" =>
            l.stats.processerrors++;
            l.logevent("precessrmsg", "Exception cought while processing Tmsg: " + e);
    }
}
Local.processrmsg(l: self ref Local, buf: array of byte)
{
    {
        (nil, msg) := Rmsg.unpack(buf);
        l.stats.recvdrmsgs++;
        l.logevent("processrmsg", "Incoming Rmsg received.");
        l.logevent("processrmsg", "Dump: " + msg.text());
        if (!msg.targetid.eq(l.node.id))
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
    exception e
    {
        "fail:*" =>
            l.stats.processerrors++;
            l.logevent("precessrmsg", "Exception cought while processing Rmsg: " + e);
    }
}
Local.changeserver(l: self ref Local)
{
    availableservers := l.contacts.getpublicnodes();
    if (len availableservers == 0)
        return;
    ind := abs(random->randomint(random->NotQuiteRandom) % len availableservers);
    newserver := availableservers[ind];
    if (newserver.id.eq(l.node.srvid))
    {
        ind++;
        ind %= len availableservers;
        newserver = availableservers[ind];
    }
    # TODO: A little race here
    l.node.srvid = newserver.id;
    l.node.srvaddr = newserver.pubaddr;
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
                l.logevent("timer", "Refreshing bucket " + string i);
                randomkey := l.contacts.randomidinbucket(i);
                l.dhtfindnode(randomkey, nil);
                bucket.lastaccess = curtime;
            }
        }

        # replicate and expire storage
        storage := l.store.all();
        for (rest := storage; rest != nil; rest = tl rest)
        {
            key := *Key.parse((hd rest).key[4:(BB*2+4)]); # the key is string like 'key(...)'
            itemlist := (hd rest).val;
            for (tail := itemlist; tail != nil; tail = tl tail)
            {
                item := hd tail;
                # replicate stage
                if (curtime - item.lastupdate > REPLICATE_TIME)
                {
                    l.logevent("timer", "Replicating item with key: " + key.text());
                    item.lastupdate = curtime;
                    storehelper(l, key, item);
                }
                # expire stage
                if (curtime - item.publishtime > EXPIRE_TIME)
                {
                    l.logevent("timer", "Item with key " + key.text() + " expired, removing");
                    l.storech <-= ((hd rest).key, item, nil, l.store);
                    l.stats.expiredentries++;
                }
            }
        }

        # republish our own storage 
        storage = l.ourstore.all();
        for (rest = storage; rest != nil; rest = tl rest)
        {
            key := *Key.parse((hd rest).key[4:(BB*2+4)]); # the key is string like 'key(...)'
            itemlist := (hd rest).val;
            for (tail := itemlist; tail != nil; tail = tl tail)
            {
                item := hd tail;
                if (curtime - item.publishtime > REPUBLISH_TIME)
                {
                    l.logevent("timer", "Republishing item with key: " + key.text());
                    item.publishtime = daytime->now();
                    item.lastupdate = daytime->now();
                    storehelper(l, key, item);       
                }
            }
        }

        # Server Keep-Alive and IP update
        if (curtime - l.serverlastseenalive > TKEEP_ALIVE)
        {
            l.serverlastseenalive = curtime;
            msg := ref Tmsg.Observe(Key.generate(), l.node, l.node.srvid);
            srv := ref Node(l.node.srvid, l.node.srvaddr, l.node.srvaddr, 
                                          l.node.srvaddr, l.node.srvid);
            (success, ans) := l.queryforrmsg(srv, msg, MAXRETRANSMIT, "timer");
            if (success  <= 0 || ans == nil)
            {
                l.changeserver();
                l.dhtfindnode(l.node.id, nil);
                continue;
            }
            observedaddr: string;
            pick m := ans {
                Observe =>
                    observedaddr = m.observedaddr;
            }
            if (observedaddr != l.node.pubaddr)
            {
                l.node.pubaddr = observedaddr;
                l.dhtfindnode(l.node.id, nil);
            }
        }
    }
}
# Thread-safeness functions
Local.callbacksproc(l: self ref Local)
{
    l.callbacksprocpid = sys->pctl(0, nil);

    while (1)
    {
        (action, key, channel) := <-l.callbacksch;
        case (action) {
            QAddCallback =>
                l.callbacks.insert(key, channel);
            QRemoveCallback =>
                l.callbacks.delete(key);
        }
    }
}
Local.contactsproc(l: self ref Local)
{
    l.contactsprocpid = sys->pctl(0, nil);

    while (1)
    {
        (action, node) := <-l.contactsch;
        case (action) {
            QAddContact =>
                l.contacts.addcontact(node);
            QRemoveContact =>
                l.contacts.removecontact(node.id);
        }
    }
}
Local.storeproc(l: self ref Local)
{
    l.storeprocpid = sys->pctl(0, nil);

    while (1)
    {
        (key, item, replacement, table) := <-l.storech;
        if (replacement == nil) # then delete it!
        {
            items := table.find(key);
            if (items == nil || lists->find(item, items) == nil)
                continue;
            newitemlist := lists->delete(item, items);
            table.delete(key);
            if (len newitemlist > 0)
                table.insert(key, newitemlist);
        }
        else # add or update it!
        {
            items := table.find(key);
            if (items == nil)
            {
                items = item :: nil;
                table.insert(key, items);
                continue;
            }
            newitemlist := lists->delete(item, items);
            table.delete(key);
            table.insert(key, replacement :: newitemlist);
        }
    }
}
Local.sendmsg(l: self ref Local, addr: string, data: array of byte)
{
    buffer := array [len data + Udp4hdrlen] of byte;

    hdr := Udphdr.new();
    (hdr.laddr, hdr.lport) = l.localaddr;
    # TODO: catch errors
    (hdr.raddr, hdr.rport) = dialparse(addr);
    hdr.pack(buffer, Udp4hdrlen);

    buffer[Udp4hdrlen:] = data[:];
    byteswritten := sys->write(l.conn.dfd, buffer, len buffer);
    if (byteswritten != len buffer)
    {
        l.stats.senderrors++;
        l.logevent("sendmsg", sys->sprint("Error while sending data: %r"));
    }
}
Local.sendtmsg(l: self ref Local, n: ref Node, msg: ref Tmsg): chan of ref Rmsg
{
    if (msg.targetid.eq(l.node.id))
    {
        # do not send it over the network!
        spawn l.processtmsg(msg.pack(), l.node.prvaddr);
        ch := chan of ref Rmsg;
        l.callbacksch <-= (QAddCallback, msg.uid.text(), ch);
        return ch;
    }
    l.stats.senttmsgs++;
    l.stats.sentmsgsbytype[ttag2type[tagof msg] - 100]++;
    l.logevent("sendtmsg", "Sending message to " + n.text());
    l.logevent("sendtmsg", "Dump: " + msg.text());
    ch := chan of ref Rmsg;

    buf := msg.pack();
    l.callbacksch <-= (QAddCallback, msg.uid.text(), ch);
    l.sendmsg(n.pubaddr, buf);
    if (n.pubaddr != n.prvaddr)
        l.sendmsg(n.prvaddr, buf);
    return ch;
}
Local.sendrmsg(l: self ref Local, prvaddr: string, pubaddr: string, msg: ref Rmsg)
{
    if (msg.targetid.eq(l.node.id))
    {
        # do not send it over the network!
        spawn l.processrmsg(msg.pack());
        return;
    }
    l.stats.sentrmsgs++;
    l.stats.sentmsgsbytype[rtag2type[tagof msg] - 100]++;
    l.logevent("sendrmsg", "Sending message to " + pubaddr + "/" + prvaddr);
    l.logevent("sendrmsg", "Dump: " + msg.text());

    buf := msg.pack();
    l.sendmsg(pubaddr, buf);
    if (pubaddr != prvaddr)
       l.sendmsg(prvaddr, buf);
}
Local.destroy(l: self ref Local)
{
    # just kill everybody
    l.logevent("destroy", "Quitting...");
    killpid(l.processpid);
    killpid(l.timerpid);
    killpid(l.callbacksprocpid);
    killpid(l.contactsprocpid);
    killpid(l.storeprocpid);
}

Local.setlogfd(l: self ref Local, fd: ref Sys->FD)
{
    l.logfd = fd;
}
Local.logevent(l: self ref Local, source: string, msg: string)
{
    l.stats.logentries++;
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
    l.stats.findnodecalled++;
    l.logevent("dhtfindnode", "Started to search for node " + id.text());
    l.logevent("dhtfindnode", "Starting node array size: " + string len nodes);
    if (nodes == nil)
        nodes = toref(l.contacts.findclosenodes(id));
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", "", "", Key.generate()));
    asked.insert(l.node.id.text(), ref l.node);
    (node, nil) := dhtfindnode(l, id, nodes, asked, 1, 0);
    return node;
}
Local.dhtfindvalue(l: self ref Local, id: Key): list of ref StoreItem
# Return value: should be list of array of byte?
{
    l.stats.findvaluecalled++;
    l.logevent("dhtfindvalue", "Started to search for value " + id.text());
    nodes := toref(l.contacts.findclosenodes(id));
    realnodes := array [len nodes + 1] of ref Node;
    realnodes[:] = nodes[:];
    realnodes[len nodes] = ref l.node;
    l.logevent("dhtfindvalue", "Starting nodes count: " + string len realnodes);
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", "", "", Key.generate()));
    (nil, items) := dhtfindnode(l, id, realnodes, asked, 0, 1);
    return items;
}
Local.dhtstore(l: self ref Local, key: Key, data: array of byte)
{
    l.stats.storecalled++;
    now := daytime->now();
    item := ref StoreItem(data, now, now);
    keytext := key.text();
    # insert or update (with the new timestamps) in our storage
    if (len data != 0)
        l.storech <-= (keytext, item, item, l.ourstore);
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
    asked := hashtable->new(HASHSIZE, ref Node(Key.generate(), "", "", "", Key.generate()));
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
        (node, data) := ret;
        if (node != nil && search)
        {
            spawn reaper(listench, pending);
            return ret;
        }
        if (len data > 0 && retrievevalue)
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
# Callbacks
timer(ch: chan of int, timeout: int)
{
    sys->sleep(timeout);
    ch <-= 1;
}
Local.queryforrmsg(l: self ref Local, target: ref Node, msg: ref Tmsg, retransmits: int, callroutine: string): (int, ref Rmsg) 
# (rtt, answer)
{
    for (i := 0; i < retransmits + 1; i++)
    {
        ch := l.sendtmsg(target, msg);
        sendtime := sys->millisec();
        killerch := chan of int;
        spawn timer(killerch, WAIT_TIME);

        stop := 0;
        answer: ref Rmsg;
        rtt := QTimeOut;
        alt {
            answer = <-ch =>
                spawn timerreaper(killerch);
                if (tagof msg != tagof answer)
                {
                    l.logevent(callroutine, "Received answer, but not the desired message format");
                    answer = nil;
                    break;
                }
                if (!answer.senderid.eq(target.id))
                {
                    l.logevent(callroutine, "Received answer from unexpected node");
                    answer = nil;
                    break;
                }
                rtt = sys->millisec() - sendtime;
                l.stats.totalrtt += rtt;
                l.stats.answersgot++;
                stop = 1;
            <-killerch =>
                l.logevent(callroutine, "Waiting timeout");
                answer = nil;
        }
        l.callbacksch <-= (QRemoveCallback, msg.uid.text(), nil);
        if (stop == 1)
            return (rtt, answer);
        else if (i < retransmits && !ispublic(target))
        {
            # TODO: Make it async?
            l.logevent(callroutine, sys->sprint("Direct connect failed, trying to establish randezvous at: %s", target.srvaddr));
            isdirect := l.askrandezvous(target.pubaddr, target.srvaddr, target.id, target.srvid);
            if (isdirect != RSuccess)
                l.logevent(callroutine, sys->sprint("fail:Seems that randezvous failed"));
        }
    }
    l.stats.unanswerednodes++;
    l.logevent(callroutine, "After " + string MAXRETRANSMIT + " attempts send failed");
    return (QTimeOut, nil);
}
Local.dhtping(l: self ref Local, id: Key): int
{
    l.stats.pingcalled++;
    node := l.contacts.getnode(id);
    if (node == nil)
        raise "fail:dhtping:ping node not found";

    l.logevent("dhtping", "Dht ping called with " + id.text());
    msg := ref Tmsg.Ping(Key.generate(), l.node, id);
    (rtt, reply) := l.queryforrmsg(node, msg, MAXRETRANSMIT, "dhtping");
    return rtt;
}
Local.processrandezvousquery(l: self ref Local, m: ref Tmsg.AskRandezvous, askingnode: ref Node)
{
    l.logevent("processrandezvous", "Randezvous for " + m.sender.id.text() + " <-> " + m.oppid.text() + ".");
    invitation := ref Tmsg.Invitation(Key.generate(), l.node, m.oppid,
                                                  askingnode.prvaddr, askingnode.pubaddr, askingnode.id);
    askednode := ref Node(m.oppid, m.addr, m.addr, m.addr, Key.generate());
    result := RFail;
    (rtt, reply) := l.queryforrmsg(askednode, invitation, 1, "processrandezvous");
    if (reply != nil)
        pick r := reply {
            Invitation =>
                if (r.result == SSuccess)
                    result = RSuccess;
        }

    answer := ref Rmsg.AskRandezvous(m.uid, l.node.id, askingnode.id, result);
    l.sendrmsg(askingnode.prvaddr, askingnode.pubaddr, answer);
}
Local.askrandezvous(l: self ref Local, nodeaddr, srvaddr: string, nodeid, srvid: Key): int
{
    l.logevent("askrandezvous", "Asking " + srvaddr + " for randezvous with " + nodeaddr + ".");
    askrandezvous := ref Tmsg.AskRandezvous(Key.generate(), l.node, srvid, nodeid, nodeaddr);
    server := ref Node(srvid, srvaddr, srvaddr, srvaddr, srvid);
    (rtt, reply) := l.queryforrmsg(server, askrandezvous, 0, "askrandezvous");
    result := RFail;
    if (reply != nil)
        pick r := reply {
            AskRandezvous =>
                result = r.result;
        }
    return result;
}
replacefirstnode(c: ref Contacts, toadd: ref Node, pingnode: ref Node, msg: ref Tmsg)
{
    c.local.stats.bucketoverflows++;
    (rtt, reply) := c.local.queryforrmsg(pingnode, msg, MAXRETRANSMIT, "replacefirstnode");
    if (reply == nil || rtt < 0)
    {
        #fail
        c.local.logevent("replacefirstnode", "Answer not received, killing node");
        c.local.contactsch <-= (QRemoveContact, ref Node(pingnode.id, "", "", "", Key.generate()));
        c.local.contactsch <-= (QAddContact, toadd);
    }
    else
    {
        #success
        c.local.contactsch <-= (QRemoveContact, ref Node(pingnode.id, "", "", "", Key.generate()));
        c.local.contactsch <-= (QAddContact, pingnode);
    }
}
findnode(l: ref Local, targetnode: ref Node, uid: Key, rch: chan of ref Rmsg, retrievevalue: int)
{
    l.logevent("findnode", "Findnode called, with key " + uid.text());
    msg: ref Tmsg;
    if (retrievevalue)
        msg = ref Tmsg.FindValue(Key.generate(), l.node, targetnode.id, uid);
    else
        msg = ref Tmsg.FindNode(Key.generate(), l.node, targetnode.id, uid);
    answer: ref Rmsg;
    (rtt, reply) := l.queryforrmsg(targetnode, msg, MAXRETRANSMIT, "findnode");
    rch <-= reply;
}
store(l: ref Local, where: ref Node, key: Key, value: ref StoreItem)
{
    l.logevent("store", "Store called with key " + key.text());
    l.logevent("store", "Storing to  " + where.text());
    msg := ref Tmsg.Store(Key.generate(), l.node, where.id, key, value);
    (rtt, reply) := l.queryforrmsg(where, msg, MAXRETRANSMIT, "store");
    result := SFail;
    if (reply != nil)
        pick r := reply {
        Store =>
            result = r.result;
        }
    if (result == SFail)
        l.logevent("store", "Store to " + where.id.text() + ": fail");
    else
        l.logevent("store", "Store to " + where.id.text() + ": success");
}

start(localaddr: string, bootstrap: array of ref Node, id: Key, logfd: ref Sys->FD): ref Local
{
    randomshuffle(bootstrap);
    (localip, localport) := dialparse(localaddr);
    contacts := ref Contacts(array [1] of ref Bucket, nil);
    # construct the first bucket
    contacts.buckets[0] = ref Bucket(nil,
        Key(array[BB] of { * => byte 0 }),
        Key(array[BB] of { * => byte 16rFF }),
        daytime->now());

    # try to announce connection
    # TODO: fix that! address should be parsed carefully 
    # TODO: correct the first part of dial command, should be something random
    (err, c) := sys->announce("udp!*!" + string localport);
    if (err != 0)
        return nil;

    ch := chan of ref Rmsg;
    storeitem := list of {ref StoreItem(array [0] of byte, 0, 0)};
    store := hashtable->new(STORESIZE, storeitem);
    localstore := hashtable->new(STORESIZE, storeitem);
    callbacksch := chan of (int, string, chan of ref Rmsg);
    contactsch := chan of (int, ref Node);
    storech := chan of (string, ref StoreItem, ref StoreItem, ref HashTable[list of ref StoreItem]);
    stats := ref Stats(0, 0, 0, 0, 0, 0, daytime->now(), array [Tmax - 100] of {* => 0},
        array [Tmax - 100] of {* => 0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    node := Node(id, localaddr, localaddr, localaddr, id);
    server := ref Local(node, (localip, localport), contacts, store, localstore, stats, nil,
        callbacksch, hashtable->new(CALLBACKSIZE, ch), storech, contactsch, 0, 0, 0, 0, 0, logfd, c, 0);
    server.contacts.local = server;

    spawn server.process();
    spawn server.callbacksproc();
    spawn server.contactsproc();
    spawn server.storeproc();

    pubaddr: string;
    for (i := 0; i < len bootstrap; ++i)
    {
        server.node.srvaddr = bootstrap[i].pubaddr;
        server.node.srvid = bootstrap[i].id;
        msg := ref Tmsg.Observe(Key.generate(), node, bootstrap[i].id);
        (rtt, reply) := server.queryforrmsg(bootstrap[i], msg, MAXRETRANSMIT, "start");
        if (reply != nil)
            pick r := reply {
                Observe =>
                    pubaddr = r.observedaddr;
            }
        if (pubaddr != nil)
        {
            server.node.pubaddr = pubaddr;
            break;
        }
    }
    if (pubaddr == nil && len bootstrap > 0)
    {
        server.logevent("start", "fail:none of the bootstrap servers replied");
        server.destroy();
        return nil;
    }
    if (len bootstrap == 0)
    {
        server.logevent("start", "starting a brand new dht server");
        server.node.pubaddr = localaddr;
    }

    for (i = 0; i < len bootstrap; ++i)
        contactsch <-= (QAddContact, bootstrap[i]);
    server.serverlastseenalive = daytime->now();
    spawn server.timer();

    server.dhtfindnode(id, bootstrap);

    return server;
}
