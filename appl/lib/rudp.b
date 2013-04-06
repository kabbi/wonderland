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

HASHSIZE: con 10000;
MAXCHUNKSIZE: con 190;


B:      con 32;
BB:     con B/8;
KEY:    con BB+4;
H:      con 50;

killpid(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}

Chunk: adt {
    belongsto: Key;
    seqnum: int; 
    chunkstotal: int;
    data: array of byte;
};

# GLOBAL TODO: Dht needs to know udp-metadata 

accepter(tchan: chan of ref Chunk, rchan: chan of array of byte)
{
    # Create an array of received pieces
    # Wait unless: 
    #        - timeout - send timeout message to sender and die
    #        - all parts received - assemble and send over rchan
    # TODO: Tip - do not forget to check whether we already had such part
}

sender(data: array of byte, timeout, retry: int, 
        callbacks: ref HashTable[chan of ref Chunk],
        rchan: chan of array of byte)
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
}   

listener(connfd: ref Sys->FD, 
          callbacks: ref HashTable[chan of ref Chunk], 
          ch: chan of int, rchan: chan of array of byte)
{
    ch <-= sys->pctl(0, nil);
    # Listen at given fd
    # Upon receiving: 
    #        - identify
    #        - if already have a record of it in hashtable
    #             -- send a piece to associated channel
    #             -- else: spawn new accepter
    while (1)
    {
        buffer := array [MAXCHUNKSIZE+1] of byte;
        bytesread := sys->read(connfd, buffer, len buffer);

        if (bytesread <= 0)
            raise sys->sprint("fail:readerror");

        hdr := Udphdr.unpack(buffer[:Udp4hdrlen], Udp4hdrlen);
        if (hdr == nil)
            raise "fail:Local.process:headers parsing error";

        raddr := "udp!" + hdr.raddr.text() + "!" + string hdr.rport;
        buffer = buffer[Udp4hdrlen:];

        if (bytesread < H + Udp4hdrlen)
            continue;
    }
}

wrapper(connfd: ref Sys->FD, 
        tchan: chan of (array of byte, int, int), # data, timeout, retry count
        rchan: chan of array of byte)
{
    callbacks := hashtable->new(HASHSIZE, chan of ref Chunk);
    ch: chan of int;
    spawn listener(connfd, callbacks, ch, rchan);
    listenpid := <-ch;
    while (1)
    {
        (data, timeout, retry) := <-tchan;
        if (data == nil)
            break; # terminate
        spawn sender(data, timeout, retry, callbacks, rchan);
    }
    killpid(listenpid);
}

new(connfd: ref Sys->FD, tchan: chan of (array of byte, int, int)): chan of array of byte
{
    rchan := chan of array of byte;
    spawn wrapper(connfd, tchan, rchan);
    return rchan;
}
