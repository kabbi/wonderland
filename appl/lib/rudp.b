implement Rudp;

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

include "rudp.m";

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail: init: bad module";
}

killpid(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}
timer(ch: chan of int, timeout: int)
{
    ch <-= sys->pctl(0, nil);
    sys->sleep(timeout);
    ch <-= 1;
}

rudplog(msg: string)
{
    sys->fprint(sys->fildes(2), "%s\n", msg);
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

RECEIVETIMEOUT: con 10000;
HASHSIZE:       con 31;
RECVBUFFERSIZE:  con 8192;
MAXCHUNKSIZE:   con 5000;
BIT32SZ:        con 4;
BIT64SZ:        con 8;
KEY:            con Bigkey->BB+BIT32SZ;

pkey(a: array of byte, o: int, k: Key): int
{
    return parray(a, o, k.data);
}
parray(a: array of byte, o: int, sa: array of byte): int
{
    n := len sa;
    p32(a, o, n);
    a[o+BIT32SZ:] = sa;
    return o+BIT32SZ+n;
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
        raise "fail:g32:malformed packet";
    number := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    return (number, o + BIT32SZ);
}
g64(a: array of byte, o: int): (big, int)
{
    if (o + BIT64SZ > len a)
        raise "fail:g64:malformed packet";
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
    if(o < 0 || o+BIT32SZ > len a)
        raise "fail:garray:malformed packet";
    l: int;
    (l, o) = g32(a, o);
    e := o+l;
    if(e > len a || l < 0)
        raise "fail:garray:malformed packet";
    return (a[o:e], e);
}
gkey(a: array of byte, o: int): (Key, int)
{
    (data, l) := garray(a, o);
    if (len data != Bigkey->BB)
        raise "fail:gkey:malformed packet";
    return (Key(data), l);
}

Chunk: adt {
    belongsto: Key;
    seqnum: int; 
    chunkstotal: int;
    data: array of byte;

    pack: fn(nil: self ref Chunk): array of byte;
    unpack: fn(a: array of byte): ref Chunk;
    send: fn(nil: self ref Chunk, connfd: ref Sys->FD, hdr: ref Udphdr);
};

Chunk.pack(c: self ref Chunk): array of byte
{
    # some magic here
    packetlen := BIT32SZ + KEY + BIT32SZ + BIT32SZ + BIT32SZ + len c.data;
    a := array [packetlen] of byte;
    o := 0;
    o = p32(a, o, packetlen);
    o = pkey(a, o, c.belongsto);
    o = p32(a, o, c.seqnum);
    o = p32(a, o, c.chunkstotal);
    o = parray(a, o, c.data);
    return a;
}
Chunk.unpack(a: array of byte): ref Chunk
{
    (packetlen, o) := g32(a, 0);
    if (packetlen <= 0 || packetlen >= len a)
        raise "fail:Chunk.unpack:bad packet length";
    a = a[:packetlen];
    belongsto: Key;
    seqnum, chunkstotal: int;
    data: array of byte;
    (belongsto, o) = gkey(a, o);
    (seqnum, o) = g32(a, o);
    (chunkstotal, o) = g32(a, o);
    (data, o) = garray(a, o);
    return ref Chunk(belongsto, seqnum, chunkstotal, data);
}
Chunk.send(c: self ref Chunk, connfd: ref Sys->FD, hdr: ref Udphdr)
{
    rudplog("Sending chunk to " + hdr.raddr.text() + "!" + string hdr.rport);
    packedchunk := c.pack();
    packet := array [len packedchunk + Udp4hdrlen] of byte;
    hdr.pack(packet, Udp4hdrlen);
    packet[Udp4hdrlen:] = packedchunk[:];
    sys->write(connfd, packet, len packet);
}

# GLOBAL TODO: Dht needs to know udp-metadata 

accepter(packetid: Key, callbacks: ref HashTable[chan of ref Chunk],
        hdr: ref Udphdr, rchan: chan of array of byte, connfd: ref Sys->FD,
        chunkstotal: int)
{
    # Create an array of received pieces
    # Wait unless: 
    #        - timeout - send timeout message to sender and die
    #        - all parts received - assemble and send over rchan
    # TODO: Tip - do not forget to check whether we already had such part

    rudplog("Starting accepter for: " + packetid.text());
    callback := callbacks.find(packetid.text());

    chunks := array [chunkstotal] of ref Chunk;
    # get all the chunks, if we had timeout - just stop
    gotchunks := 0;
    gottimeout := 0;
    while (gotchunks != len chunks && gottimeout != 1)
    {
        killerch := chan of int;
        spawn timer(killerch, RECEIVETIMEOUT);
        timerpid := <-killerch;
        rudplog("Waiting for anything to happen");
        alt {
            chunk := <-callback =>
                # got a chunk, add it, rewind the timer and go on
                rudplog("Got chunk " +
                    string chunk.seqnum + " of " + 
                    string chunk.chunkstotal + " from " +
                    hdr.raddr.text() + "!" + string hdr.rport);
                killpid(timerpid);
                if (chunk.seqnum >= len chunks)
                    break; # malformed data, ignore
                if (chunks[chunk.seqnum] == nil)
                    gotchunks++;
                chunks[chunk.seqnum] = chunk;
                # send some acknowledgement
                ack := ref Chunk(packetid, chunk.seqnum, chunk.chunkstotal,
                    array [0] of byte);
                ack.send(connfd, hdr);
                rudplog("Sending ack");
            <-killerch =>
                # so sad, break
                gottimeout = 1;
                rudplog("Accepter timeout, exiting");
        }
    }
    rudplog("Accepter results: got " +
        string gotchunks + " of " +
        string len chunks);
    if (gotchunks == len chunks)
    {
        rudplog("Full packet, passing back to user");
        # we have a full packet, assemble and return to sender
        datalen := 0;
        for (i := 0; i < len chunks; i++)
            datalen += len chunks[i].data;
        packet := array [Udp4hdrlen + datalen] of byte;
        hdr.pack(packet, Udp4hdrlen);
        packetptr := Udp4hdrlen;
        for (i = 0; i < len chunks; i++)
        {
            chunklen := len chunks[i].data;
            packet[packetptr:] = chunks[i].data;
            packetptr += chunklen;
        }
        rchan <-= packet;
    }
    rudplog("Deleting callback: " + packetid.text());
    callbacks.delete(packetid.text());
}

sender(connfd: ref Sys->FD, data: array of byte, timeout, retry: int, 
       callbacks: ref HashTable[chan of ref Chunk])
{
    # Splice into pieces
    # Create hashtable of acknowledged datagrams
    # Send all of them and create a kill-timer
    # Upon receiving acknowledgement (by channel): 
    #        - rewind timer, 
    #        - mark as acknowledged 
    #        - check if we've acknowleged all of them
    #            -- then assemble result and return it to rchan
    # If killed by timer -> resend it, increment retry count
    # If retry count equals @retry -> return nil

    # extract destination info
    hdr := Udphdr.unpack(data[:Udp4hdrlen], Udp4hdrlen);
    if (hdr == nil)
        return; # ignore the fail
    rudplog("Starting sender for: " + hdr.raddr.text() + "!" + string hdr.rport);
    data = data[Udp4hdrlen:];
    # setup callbacks
    packetuid := Key.generate();
    callbackch := chan of ref Chunk;
    callbacks.insert(packetuid.text(), callbackch);
    # split the data into chunks
    chunkstotal := len data / MAXCHUNKSIZE;
    if (chunkstotal * MAXCHUNKSIZE < len data)
        chunkstotal++;
    rudplog("Splitting the packet into " + string chunkstotal + " chunks");
    chunks := array [chunkstotal] of ref Chunk;
    chunkacks := array [chunkstotal] of {* => 0};
    for (i := 0; i < chunkstotal; i++)
    {
        lowerbound := MAXCHUNKSIZE * i;
        uppedbound := MAXCHUNKSIZE * (i + 1);
        if (uppedbound > len data)
            uppedbound = len data;
        chunks[i] = ref Chunk(packetuid, i, chunkstotal,
            data[lowerbound:uppedbound]);
    }

    # start getting answers
    gotanswers := 0;
    for (i = 0; i < retry; i++)
    {
        trymore := 0;
        rudplog("Sending remaining " + string (chunkstotal - gotanswers) + " chunks");
        # resend unacknowledged chunks
        for (j := 0; j < chunkstotal; j++)
            if (chunkacks[j] == 0)
                chunks[j].send(connfd, hdr);
        # listen for acks
        gottimeout := 0;
        while (gotanswers != chunkstotal && gottimeout != 1)
        {
            killerch := chan of int;
            spawn timer(killerch, timeout);
            timerpid := <-killerch;
            rudplog("Listening for ack");
            alt {
                answer := <-callbackch =>
                    killpid(timerpid);
                    ackedchunk := answer.seqnum;
                    rudplog("Weee, got an ack for " + string answer.seqnum);
                    if (chunkacks[ackedchunk] == 0)
                        gotanswers++;
                    chunkacks[ackedchunk] = 1;
                    trymore = 1;
                <-killerch =>
                    rudplog("Got timeout");
                    # so sad, break
                    gottimeout = 1;
            }
        }
        if (trymore == 1)
            i--;
        if (gottimeout == 0) {
            rudplog("Send finished, all acks received");
            return; # we did it!
        }
    }
    # do some work of telling the issuer about timeout
    # if it's actually needed
    rudplog("Timeout waiting acks after " + string retry + " attempts");
}

listener(connfd: ref Sys->FD, 
         callbacks: ref HashTable[chan of ref Chunk], 
         pidch: chan of int, rchan: chan of array of byte)
{
    rudplog("Starting listener");
    pidch <-= sys->pctl(0, nil);
    # Listen at given fd
    # Upon receiving: 
    #        - identify
    #        - if already have a record of it in hashtable
    #             -- send a piece to associated channel
    #             -- else: spawn new accepter
    while (1)
    {
        buffer := array [RECVBUFFERSIZE] of byte;
        bytesread := sys->read(connfd, buffer, len buffer);

        if (bytesread <= 0)
            raise sys->sprint("fail:readerror");

        hdr := Udphdr.unpack(buffer[:Udp4hdrlen], Udp4hdrlen);
        if (hdr == nil)
            continue;

        rudplog("Got packet from network from " + hdr.raddr.text() + ":" + string hdr.rport);

        raddr := "udp!" + hdr.raddr.text() + "!" + string hdr.rport;
        buffer = buffer[Udp4hdrlen:];

        if (bytesread < Udp4hdrlen)
            continue;

        {
            chunk := Chunk.unpack(buffer);
            belongsto := chunk.belongsto.text();
            callback := callbacks.find(belongsto);
            rudplog("Searching for callback for " + belongsto);
            if (callback == nil)
            {
                callback = chan of ref Chunk;
                callbacks.insert(belongsto, callback);
                rudplog("No callback exists, starting new accepter");
                spawn accepter(chunk.belongsto, callbacks,
                    hdr, rchan, connfd, chunk.chunkstotal);
            }
            callback <-= chunk;
        }
        exception e
        {
            "fail:*" =>
                rudplog("Error handling packet: " + e);
        }
    }
}

wrapper(connfd: ref Sys->FD, 
        tchan: chan of (array of  byte, int, int), # data, timeout, retry count
        rchan: chan of array of byte)
{
    rudplog("Wrapper started");
    callbacks := hashtable->new(HASHSIZE, chan of ref Chunk);
    pidch := chan of int;
    spawn listener(connfd, callbacks, pidch, rchan);
    listenpid := <-pidch;
    while (1)
    {
        rudplog("Waiting for some task");
        (data, timeout, retry) := <-tchan;
        rudplog("Got some data (" + string len data + ") from user, processing");
        if (len data == 0)
            break; # terminate
        sender(connfd, data, timeout, retry, callbacks);
    }
    rudplog("Terminating");
    killpid(listenpid);
}

new(connfd: ref Sys->FD, tchan: chan of (array of byte, int, int)): chan of array of byte
{
    rchan := chan of array of byte;
    spawn wrapper(connfd, tchan, rchan);
    return rchan;
}
