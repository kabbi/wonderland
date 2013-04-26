implement Rudpping;

include "sys.m";
    sys: Sys;
include "draw.m";
include "ip.m";
    ip: IP;
    IPaddr, Udphdr, Udp4hdrlen: import ip;
include "keyring.m";
include "security.m";
    random: Random;
include "rudp.m";
    rudp: Rudp;


packetsize := 10000;
listenaddr := "";
sendaddr := "";
mode := 0;
listenerpid := 0;

Rudpping: module
{
    init:   fn(ctxt: ref Draw->Context, args: list of string);
};

usage(progname: string)
{
    sys->print("%s <listenaddr> <sendaddr> -[s|r] [packetsize]", progname);
    exit;
}

parseargs(args: list of string)
{
    progname := hd args;
    args = tl args;
    if (args == nil)
        usage(progname);
    listenaddr = hd args;
    args = tl args;
    if (args == nil)
        usage(progname);
    sendaddr = hd args;
    args = tl args;
    if (args == nil)
        usage(progname);
    mode = 0;
    if (hd args == "-s")
        mode = 1;
    args = tl args;
    packetsize = 20000;
    if (args != nil)
        packetsize = int hd args;
}

init(ctxt: ref Draw->Context, args: list of string)
{
    sys = load Sys Sys->PATH;
    random = load Random Random->PATH;
    ip = load IP IP->PATH;
    ip->init();
    rudp = load Rudp Rudp->PATH;
    rudp->init();
    parseargs(args);

    tchan: chan of (array of byte, int, int); 
    {
        (listenip, listenport) := dialparse(listenaddr);
        (sendip, sendport) := dialparse(sendaddr);
        (err, c) := sys->announce("udp!*!" + string listenport);
        if (err != 0)
            raise sys->sprint("fail:cant connect:%r");
        sys->fprint(c.cfd, "headers4");
        c.dfd = sys->open(c.dir + "/data", Sys->ORDWR);
        tchan = chan of (array of byte, int, int); 

        if (mode) {
            rchan := rudp->new(c.dfd, tchan);
            sys->print("Communicating with %s\n", sendaddr);
            sys->print("Sent packet: %d bytes\n", packetsize);

            packet := array [Udp4hdrlen + packetsize] of byte;
            hdr := Udphdr.new();
            (hdr.laddr, hdr.lport) = (listenip, listenport);
            (hdr.raddr, hdr.rport) = (sendip, sendport);
            hdr.pack(packet, Udp4hdrlen);
            packet[Udp4hdrlen] = byte 42;
            tchan <-= (packet, 1000, 3);
            # block
            dummy := array [1] of byte;
            sys->read(sys->fildes(0), dummy, len dummy);
        }
        else {
            rchan := rudp->new(c.dfd, tchan);
            spawn listener(rchan, tchan);
            sys->print("Listening for arriving packets\n");
            # block forever
            while (1) {
                sys->sleep(10000);
            }
        }
    }
    exception e {
        "*" =>
            sys->print("Critical error: %s\n", e);
            sys->print("Exiting\n");
    }
    if (tchan != nil)
        tchan <-= (array [0] of byte, 0, 0);
    if (listenerpid != 0)
        killpid(listenerpid);
}

listener(rchan: chan of array of byte, tchan: chan of (array of byte, int, int))
{
    listenerpid = sys->pctl(0, nil);
    while (1) {
        data := <-rchan;
        if (len data <= Udp4hdrlen)
            sys->print("Packet too short\n");
        hdr := Udphdr.unpack(data, Udp4hdrlen);
        data = data[Udp4hdrlen:];
        sys->print("Packet from: %s:%d, %d bytes\n", hdr.raddr.text(),
            hdr.rport, len data);
        if (int data[0] != 42)
            sys->print("Packet format error\n");
    }
}

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

killpid(pid: int)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "kill");
}
