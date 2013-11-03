implement RudpTest;

include "sys.m";
    sys: Sys;
include "draw.m";
include "ip.m";
    ip: IP;
    IPaddr, Udphdr, Udp4hdrlen: import ip;
include "keyring.m";
include "security.m";
    random: Random;
include "hashtable.m";
    hashtable: Hashtable;
    HashTable: import hashtable;
include "rudp.m";
    rudp: Rudp;

SEND_TIMEOUT: con 700;
SEND_MAX_RETRANSMIT: con 200;
SEND_DELAY: con 1000;
MAX_PACKET_SIZE: con 100000;
REPORT_STATS_EVERY_NTH_PACKET: con 10;
REPORT_STATS_RESOLUTION: con 10;
REPORT_STATS_STEP: con (255 / REPORT_STATS_RESOLUTION);

receiveStats := array [256] of int;

usage(progname: string)
{
    sys->print("%s <listenaddr> [<sendaddr>]", progname);
    exit;
}

RudpTest: module
{
    init: fn(ctxt: ref Draw->Context, argv: list of string);
};

init(ctxt: ref Draw->Context, argv: list of string)
{
    sys = load Sys Sys->PATH;
    random = load Random Random->PATH;
    ip = load IP IP->PATH;
    ip->init();
    rudp = load Rudp Rudp->PATH;
    rudp->init();
    #rudp->setlogfd(sys->fildes(1));
    hashtable = load Hashtable Hashtable->PATH;

    if (len argv < 2 || len argv > 3)
        usage(hd argv);
    argv = tl argv;

    grpid := sys->pctl(Sys->NEWPGRP, nil);
    rudplog(sys->sprint("[init] Making new process group %d", grpid));

    (listenip, listenport) := addrparse(hd argv);
    rudplog(sys->sprint("[init] Listening on udp!%s!%d", listenip.text(), listenport));
    argv = tl argv;

    (err, c) := sys->announce("udp!*!" + string listenport);
    if (err != 0)
        raise sys->sprint("fail:can't connect:%r");
    sys->fprint(c.cfd, "headers4");
    c.dfd = sys->open(c.dir + "/data", Sys->ORDWR);
    tchan := chan of (array of byte, int, int);
    rchan := rudp->new(c.dfd, tchan);
    killch := chan of int;
    spawn listener(killch, tchan, rchan);
    spawn controller(killch);

    if (argv != nil)
        spawn sender(hd argv, listenip, listenport, tchan);

    <-killch;
    killgrp(grpid);
}

sender(sendaddr: string, localip: IPaddr, localport: int, tchan: chan of (array of byte, int, int))
{
    sys->sleep(SEND_DELAY);
    (sendip, sendport) := addrparse(sendaddr);
    rudplog(sys->sprint("[sender] Sending starting packet to udp!%s!%d", sendip.text(), sendport));

    data := array [Udp4hdrlen + 5] of byte;
    p32(data, Udp4hdrlen, len data - Udp4hdrlen);
    data[Udp4hdrlen + 4] = byte 3;
    hdr := Udphdr.new();
    hdr.laddr = localip;
    hdr.lport = localport;
    hdr.raddr = sendip;
    hdr.rport = sendport;
    hdr.pack(data, Udp4hdrlen);
    tchan <-= (data, SEND_TIMEOUT, SEND_MAX_RETRANSMIT);
    rudplog("[sender] Initial packet sent, sender finished");
}

listener(killch: chan of int, tchan: chan of (array of byte, int, int), rchan: chan of array of byte)
{
    rudplog("[listener] Awaiting incoming connections");
    while (1) {
        data := <-rchan;
        if (len data <= Udp4hdrlen) {
            rudplog("[listener] Received packet is smaller than udp4 header: " + string len data + " bytes");
            continue; 
        }

        hdr := Udphdr.unpack(data, Udp4hdrlen);
        data = data[Udp4hdrlen:];

        #rudplog(sys->sprint("[listener] Packet from: udp!%s!%d, %d bytes", hdr.raddr.text(), hdr.rport, len data));
        if (len data < 4) {
            rudplog("[listener] The received packet is too short");
            continue;
        }

        (clen, nil) := g32(data, 0);
        if (len data != clen) {
            rudplog("[listener] Packet length error, expected " + string clen + " bytes");
            continue;
        }

        seq := data[4];
        #rudplog("[listener] Packet seq number: " + string seq);
        receiveStats[int seq] += 1;

        randomlen := rand(MAX_PACKET_SIZE);
        #rudplog("[listener] Passing packet back, appending " + string randomlen + " bytes of random data");
        newdata := array [Udp4hdrlen + 5 + randomlen] of byte;
        p32(newdata, Udp4hdrlen, len newdata - Udp4hdrlen);
        newdata[Udp4hdrlen + 4] = seq + byte 1;
        newdata[Udp4hdrlen + 5:] = random->randombuf(Random->NotQuiteRandom, randomlen);

        newhdr := Udphdr.new();
        newhdr.raddr = hdr.laddr;
        newhdr.laddr = hdr.raddr;
        newhdr.lport = hdr.rport;
        newhdr.rport = hdr.lport;
        hdr.pack(newdata, Udp4hdrlen);
        tchan <-= (newdata, SEND_TIMEOUT, SEND_MAX_RETRANSMIT);
        #rudplog("[listener] Packet sent");
    }
}

controller(killch: chan of int)
{
    rudplog("[controller] Waiting for user command. Type ? for help");
    while (1) {
        buf := array [8192] of byte;
        readcnt := sys->read(sys->fildes(0), buf, len buf);

        line := string buf[:readcnt - 1]; # also strip \n

        (argcount, args) := sys->tokenize(line, " ");
        if (argcount == 0)
            continue;

        case (hd args) {
            "help" or "?" =>
                rudplog("[controller] The Help");
            "quit" or "kill" or "die" or "q" =>
                killch <-= 1;
                return;
            "rudplog" =>
                if (args == nil)
                    rudp->setlogfd(sys->fildes(1));
                else
                    rudp->setlogfd(sys->open(hd tl args, Sys->OWRITE));
            "stats" or "s" =>
                reportstats();
            "fails" or "f" =>
                rudplog("[rudp] " + rudp->stats());
        }
    }
}

reportstats()
{
    report := "Report: ";
    for (i := 0; i < 255; i += REPORT_STATS_STEP) {
        sum := 0;
        for (j := 0; j < REPORT_STATS_RESOLUTION && (i + j) < len receiveStats; j++)
            sum += receiveStats[i + j];
        report += string (sum / j) + ", ";
    }
    rudplog("[stats] " + report);
}

p32(a: array of byte, o: int, v: int): int
{
    a[o] = byte v;
    a[o + 1] = byte (v>>8);
    a[o + 2] = byte (v>>16);
    a[o + 3] = byte (v>>24);
    return o + 4;
}
g32(a: array of byte, o: int): (int, int)
{
    number := (((((int a[o+3] << 8) | int a[o+2]) << 8) | int a[o+1]) << 8) | int a[o];
    return (number, o + 4);
}

rand(max: int): int
{
    r := random->randomint(Random->NotQuiteRandom);
    if (r < 0)
        r = -r;
    return r % max;
}

killgrp(pid: int)
{
    fd := sys->open("#p/" + (string pid) + "/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "killgrp");
}

rudplog(msg: string)
{
    sys->print("[rudptest] %s\n", msg);
}

addrparse(addr: string): (IPaddr, int)
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