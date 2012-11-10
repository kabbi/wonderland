implement Dht;

include "sys.m";
    sys: Sys;
include "keyring.m";
    keyring: Keyring;
include "encoding.m";
    base32: Encoding;
include "security.m";
    random: Random;
include "daytime.m";
    daytime: Daytime;
include "math.m";
    math: Math;

include "dht.m";

# different data structure sizes in bytes
LEN: con BIT32SZ;   # string and array length field
COUNT: con BIT32SZ;
OFFSET: con BIT64SZ;
KEY: con BB+LEN;
NODE: con KEY+LEN+BIT32SZ;

H: con BIT32SZ+BIT8SZ+BIT32SZ+KEY+KEY;  # minimum header length: size[4] type tag[4] sender[20] target[20]

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

init()
{
    sys = load Sys Sys->PATH;
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load keyring: %r\n");
        raise "fail:bad module";
    }
    base32 = load Encoding Encoding->BASE32PATH;
    if (base32 == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load base64: %r\n");
        raise "fail:bad module";
    }
    random = load Random Random->PATH;
    if (random == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load random: %r\n");
        raise "fail:bad module";
    }
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load daytime: %r\n");
        raise "fail:bad module";
    }
    math = load Math Math->PATH;
    if (math == nil)
    {
        sys->fprint(sys->fildes(2), "cannot load math: %r\n");
        raise "fail:bad module";
    }
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
    sa := array of byte s;  # could do conversion ourselves
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

g32(f: array of byte, i: int): int
{
    return (((((int f[i+3] << 8) | int f[i+2]) << 8) | int f[i+1]) << 8) | int f[i];
}

g64(f: array of byte, i: int): big
{
    b0 := (((((int f[i+3] << 8) | int f[i+2]) << 8) | int f[i+1]) << 8) | int f[i];
    b1 := (((((int f[i+7] << 8) | int f[i+6]) << 8) | int f[i+5]) << 8) | int f[i+4];
    return (big b1 << 32) | (big b0 & 16rFFFFFFFF);
}

gstring(a: array of byte, o: int): (string, int)
{
    (str, l) := garray(a, o);
    if (str == nil)
        return (nil, -1);
    return (string str, l);
}

garray(a: array of byte, o: int): (array of byte, int)
{
    if(o < 0 || o+LEN > len a)
        return (nil, -1);
    l := (int a[o+1] << 8) | int a[o];
    o += LEN;
    e := o+l;
    if(e > len a)
        return (nil, -1);
    return (a[o:e], e);
}

gkey(a: array of byte, o: int): (ref Key, int)
{
    (data, l) := garray(a, o);
    if (data == nil)
        return (nil, -1);
    if (len data != BB)
        return (nil, -1);
    return (ref Key(data), l);
}

gnode(a: array of byte, o: int): (ref Node, int)
{
    (key, o1) := gkey(a, o);
    if (key == nil)
        return (nil, -1);
    (addr, o2) := gstring(a, o1);
    if (addr == nil)
        return (nil, -1);
    rtt := g32(a, o2);
    return (ref Node(*key, addr, rtt), o2+BIT32SZ);
}

gnodes(a: array of byte, o: int): (array of Node, int)
{
    # TODO: implement
    return (nil, -1);
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
        # no data
    Store =>
        ml += len m.data;
    FindNode or FindValue =>
        # no data
    }
    return ml;
}

Tmsg.pack(t: self ref Tmsg): array of byte
{
    if(t == nil)
        return nil;
    ds := t.packedsize();
    if(ds <= 0)
        return nil;
    d := array [ds] of byte;
    o := 0; # offset
    o = p32(d, o, ds);
    d[o++] = byte ttag2type[tagof t];
    o = p32(d, o, t.tag);
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
        raise sys->sprint("assertion: Styx->Tmsg.pack: bad tag: %d", tagof t);
    }
    return d;
}

Tmsg.unpack(f: array of byte): (int, ref Tmsg)
{
    if(len f < H)
        return (0, nil);
    size := g32(f, 0);
    if(len f != size){
        if(len f < size)
            return (0, nil);    # need more data
        f = f[0:size];  # trim to exact length
    }
    mtype := int f[4];
    if(mtype >= len hdrlen || (mtype&1) != 0 || size < hdrlen[mtype])
        return (-1, nil);

    tag := g32(f, 5);
    (sender, o1) := garray(f, 9);
    if (sender == nil)
        return (-1, nil);
    senderID := Key(sender);
    (target, o2) := garray(f, o1);
    if (target == nil)
        return (-1, nil);
    targetID := Key(target);
    if (o2 != H)
        return (-1, nil);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        sys->print("styx: Tmsg.unpack: bad type %d\n", mtype);
    TPing =>
        return (H, ref Tmsg.Ping(tag, senderID, targetID));
    TStore =>
        key: Key;
        (keyData, nil) := garray(f, H);
        if (keyData == nil)
            break;
        key.data = keyData;
        (data, o) := garray(f, H+BB);
        ask := g32(f, o);
        return (o, ref Tmsg.Store(tag, senderID, targetID, key, data, ask));
    TFindNode =>
        key: Key;
        (keyData, o) := garray(f, H);
        if (keyData == nil)
            break;
        return (o, ref Tmsg.FindNode(tag, senderID, targetID, key));
    TFindValue =>
        key: Key;
        (keyData, o) := garray(f, H);
        if (keyData == nil)
            break;
        return (o, ref Tmsg.FindValue(tag, senderID, targetID, key));
    }
    return (-1, nil);       # illegal
}

tmsgname := array[] of {
tagof Tmsg.Ping => "Ping",
tagof Tmsg.Store => "Store",
tagof Tmsg.FindNode => "FindNode",
tagof Tmsg.FindValue => "FindValue"
};

Tmsg.text(t: self ref Tmsg): string
{
    if(t == nil)
        return "nil";
    s := sys->sprint("Tmsg.%s(%ud,%s->%s,", tmsgname[tagof t], t.tag, (ref t.senderID).text(), (ref t.targetID).text());
    pick m:= t {
    * =>
        return s + ",ILLEGAL)";
    Ping =>
        # no data
        return s + ")";
    Store =>
        return s + sys->sprint("%s,arr[%ud],%ud)", (ref m.key).text(), len m.data, m.ask);
    FindNode or FindValue =>
        return s + sys->sprint("%s)", (ref m.key).text());
    }
}

Tmsg.read(fd: ref Sys->FD, msglim: int): ref Tmsg
{
    (msg, err) := readmsg(fd, msglim);
    if(err != nil || msg == nil)
        return nil;
    (nil, m) := Tmsg.unpack(msg);
    if(m == nil)
        nil;
    return m;
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
        # no data
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
    if(r == nil)
        return nil;
    ds := r.packedsize();
    if(ds <= 0)
        return nil;
    d := array [ds] of byte;
    o := 0; # offset
    o = p32(d, o, ds);
    d[o++] = byte ttag2type[tagof r];
    o = p32(d, o, r.tag);
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
        raise sys->sprint("assertion: Styx->Rmsg.pack: bad tag: %d", tagof r);
    }
    return d;
}

Rmsg.unpack(f: array of byte): (int, ref Rmsg)
{
    if(len f < H)
        return (0, nil);
    size := g32(f, 0);
    if(len f != size){
        if(len f < size)
            return (0, nil);    # need more data
        f = f[0:size];  # trim to exact length
    }
    mtype := int f[4];
    if(mtype >= len hdrlen || (mtype&1) != 0 || size < hdrlen[mtype])
        return (-1, nil);

    tag := g32(f, 5);
    (sender, o1) := garray(f, 9);
    if (sender == nil)
        return (-1, nil);
    senderID := Key(sender);
    (target, o2) := garray(f, o1);
    if (target == nil)
        return (-1, nil);
    targetID := Key(target);
    if (o2 != H)
        return (-1, nil);

    # return out of each case body for a legal message;
    # break out of the case for an illegal one

    case mtype {
    * =>
        sys->print("styx: Rmsg.unpack: bad type %d\n", mtype);
    TPing =>
        return (H, ref Rmsg.Ping(tag, senderID, targetID));
    TStore =>
        result := g32(f, H);
        return (H+BIT32SZ, ref Rmsg.Store(tag, senderID, targetID, result));
    TFindNode =>
        # implement reading!
        nodes := array [1] of Node;
        return (0, ref Rmsg.FindNode(tag, senderID, targetID, nodes));
    TFindValue =>
        # implement reading!
        result := g32(f, H);
        nodes := array [1] of Node;
        value := array [1] of byte;
        return (0, ref Rmsg.FindValue(tag, senderID, targetID, result, nodes, value));
    }
    return (-1, nil);       # illegal
}

Rmsgname := array[] of {
tagof Rmsg.Ping => "Ping",
tagof Rmsg.Store => "Store",
tagof Rmsg.FindNode => "FindNode",
tagof Rmsg.FindValue => "FindValue"
};

Rmsg.text(r: self ref Rmsg): string
{
    if(r == nil)
        return "nil";
    s := sys->sprint("Rmsg.%s(%ud,%s->%s,", Rmsgname[tagof r], r.tag, (ref r.senderID).text(), (ref r.targetID).text());
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
    (msg, err) := readmsg(fd, msglim);
    if(err != nil || msg == nil)
        return nil;
    (nil, m) := Rmsg.unpack(msg);
    if(m == nil)
        nil;
    return m;
}

readmsg(fd: ref Sys->FD, msglim: int): (array of byte, string)
{
    if(msglim <= 0)
        msglim = MAXRPC;
    sbuf := array[BIT32SZ] of byte;
    if((n := sys->readn(fd, sbuf, BIT32SZ)) != BIT32SZ){
        if(n == 0)
            return (nil, nil);
        return (nil, sys->sprint("%r"));
    }
    ml := g32(sbuf, 0);
    if(ml <= BIT32SZ)
        return (nil, "invalid DHT message size");
    if(ml > msglim)
        return (nil, "DHT message longer than agreed");
    buf := array[ml] of byte;
    buf[0:] = sbuf;
    if((n = sys->readn(fd, buf[BIT32SZ:], ml-BIT32SZ)) != ml-BIT32SZ){
        if(n == 0)
            return (nil, "DHT message truncated");
        return (nil, sys->sprint("%r"));
    }
    return (buf, nil);
}

istmsg(f: array of byte): int
{
    if(len f < H)
        return -1;
    return (int f[BIT32SZ] & 1) == 0;
}

Key.text(k: self ref Key): string
{
    return sys->sprint("Key(%s)", base32->enc(k.data));
}
Key.generate(): Key
{
    data := array [BB] of byte;
    # TODO: replace NotQuiteRandom with ReallyRandom
    randdata := random->randombuf(random->NotQuiteRandom, RANDOMNESS);
    keyring->sha1(randdata, len randdata, data, nil);
    return Key(data);
}
Key.frompow2(pow: int): Key
{
    data := array [BB] of { * => byte 0 };
    if (pow < 160)
        data[pow / 8] = byte (1 << (pow % 8));
    else
        data = array [BB] of { * => byte 16rFF };
    return Key(data);
}
Key.lt(k: self ref Key, o: ref Key): int
{
    for (i := BB - 1; i >= 0; i--)
        if (k.data[i] != o.data[i])
            return k.data[i] < o.data[i];
    return 0;
}
Key.gt(k: self ref Key, o: ref Key): int
{
    for (i := BB - 1; i >= 0; i--)
        if (k.data[i] != o.data[i])
            return k.data[i] > o.data[i];
    return 0;
}

Node.text(n: self ref Node): string
{
    return sys->sprint("Node(%s,%s,%ud)", (ref n.id).text(), n.addr, n.rtt);
}

Bucket.isinrange(b: self ref Bucket, id: Key): int
{
    bot := Key.frompow2(b.minrange);
    top := Key.frompow2(b.maxrange);
    return !(ref id).gt(ref top) && !(ref id).lt(ref bot);
}
Bucket.addnode(b: self ref Bucket, n: Node): int
{
    if (len b.nodes >= K)
        return EBucketFull;
    if (b.findnode(n.id) != -1)
        return EAlreadyPresent; # Wouldn't it be better to automaticaly update?
    b.nodes[len b.nodes] = n; 
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
    for (i := 0; i<len b.nodes; i++)
        if (b.nodes[i].id.data == id.data)
            return i;
    # not found
    return -1;
}
Bucket.print(b: self ref Bucket, tabs: int)
{
    indent := string array[tabs] of {* => byte '\t'}; 

    sys->print("%s(Bucket [lastaccess=%s]\n", indent, daytime->text(ref b.lastaccess));
    sys->print("%s        [minrange=%s]\n", indent, (ref Key.frompow2(b.minrange)).text());
    sys->print("%s        Nodes:\n", indent);
    for (i := 0; i < len b.nodes; i++)
        sys->print("%s             %s:\n", indent, (ref b.nodes[i]).text());
    sys->print("%s        [maxrange=%s])\n", indent, (ref Key.frompow2(b.maxrange)).text());
}

Contacts.addcontact(c: self ref Contacts, n: ref Node)
{
    bucketInd := c.findbucket(n.id);
    #TODO: Update lastaccess time?
    case (ref c.buckets[bucketInd]).addnode(*n)
    {
        * =>
            #Success, nothing to do here.
        EBucketFull => 
        #TODO: Substitute to section 2.2 (see l.152 of p2plib)
        if ((ref c.buckets[bucketInd]).isinrange(c.localid))
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
    l := ref Bucket(array [0] of Node, src.minrange, (src.minrange + src.maxrange) / 2, src.lastaccess);
    r := ref Bucket(array [0] of Node, l.minrange + 1, src.maxrange, src.lastaccess);
    for (i := 0; i < len src.nodes; i++)
    {
        n := ref src.nodes[i];
        if (l.isinrange(n.id))
            l.addnode(*n);
        else
            r.addnode(*n);
    }
    c.buckets[idx+2:] = c.buckets[idx+1:];
    c.buckets[idx] = *l;
    c.buckets[idx+1] = *r;
}
Contacts.removecontact(c: self ref Contacts, id: Key)
{
    trgbucket := ref c.buckets[c.findbucket(id)];
    # construct and find dummy Node
    idx := trgbucket.findnode(id);
    nodes := array [len trgbucket.nodes - 1] of Node;
    nodes[:] = trgbucket.nodes[:idx];
    nodes[idx:] = trgbucket.nodes[idx+1:];
    trgbucket.nodes = nodes;
}
Contacts.findbucket(c: self ref Contacts, id: Key): int
{
    for (i := 0; i < len c.buckets; i++)
        if ((ref c.buckets[i]).isinrange(id))
            return i;
    # not found
    return -1;
}
Contacts.randomidinbucket(c: self ref Contacts, idx: int): Key
{
    b := c.buckets[idx];
    l := array [BB] of byte;
    l[b.minrange / 8] = byte (1 << (b.minrange % 8));
    h := array [BB] of byte;
    for (i := 0; i <= b.maxrange/8; i++)
        h[i] = byte 16rFF;
    h[i + 1] = byte ((1 << ((b.maxrange + 1) % 8)) - 1);

    ret := Key.generate();
    for (i = 0; i < BB; i++)
    {
        ret.data[i] |= l[i];
        ret.data[i] &= h[i];
    }
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
    nodeIdx := (ref c.buckets[idx]).findnode(id);
    if (nodeIdx == -1)
        return nil;
    return ref c.buckets[idx].nodes[nodeIdx];
}
Contacts.findclosenodes(c: self ref Contacts, id: Key): array of Node
{
    bucketIdx := c.findbucket(id);
    nodes := (ref c.buckets[bucketIdx]).getnodes(K);
    (i, mod, sign) := (1, 1, 1);
    ablemove := (bucketIdx + abs(i) < len c.buckets) || (bucketIdx - abs(i) >= 0);
    buffer, newnodes: array of Node;
    while (len nodes < K && ablemove) 
    {
	    if ((bucketIdx + i < len c.buckets) && (bucketIdx + i >= 0))
	    {
	        newnodes = (ref c.buckets[bucketIdx + i]).getnodes(K - len nodes);
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
    sys->print("%sContacts [key=%s]\n", indent, (ref c.localid).text());
    for (i := 0; i < len c.buckets; i++)
        (ref c.buckets[i]).print(tabs + 1);
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
    killpid(l.processpid);
    killpid(l.timerpid);
}


start(localaddr: string, bootstrap: ref Node, id: Key): ref Local
{
    node := Node(id, localaddr, 0);
    contacts := Contacts(array [1] of Bucket, id);
    # construct the first bucket
    contacts.buckets[0] = Bucket(array [0] of Node, 0, B - 1, *daytime->local(daytime->now()));

    store: list of (Key, array of byte, Daytime->Tm);
    server := ref Local(node, contacts, store, 0, 0);

    # try to announce connection
    (err, c) := sys->announce(localaddr);
    if (err != 0)
        return nil;

    spawn server.process(c);
    spawn server.timer();

    return server;
}
