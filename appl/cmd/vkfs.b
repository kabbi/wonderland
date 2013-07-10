implement Vkfs;
include "sys.m";
    sys: Sys;
include "draw.m";
include "arg.m";
include "styx.m";
    styx: Styx;
    Rmsg, Tmsg: import styx;
include "styxservers.m";
    styxservers: Styxservers;
    Ebadfid, Enotfound, Eopen, Einuse, Eperm: import Styxservers;
    Styxserver, readbytes, readstr, Navigator, Fid: import styxservers;
    nametree: Nametree;
    Tree: import nametree;
include "daytime.m";
    daytime: Daytime;
include "string.m";
    str: String;
include "lists.m";
    lists: Lists;
include "hashtable.m";
    hashtable: Hashtable;
    HashTable: import hashtable;
include "keyring.m";
    keyring: Keyring;
include "ip.m";
    ip: IP;
    IPaddr: import ip;
include "bufio.m";
    bufio: Bufio;
    Iobuf: import bufio;
include "json.m";
    json: JSON;
    JValue: import json;
include "regex.m";
    regex: Regex;
    Re: import regex;

Vkfs: module {
    init: fn(nil: ref Draw->Context, argv: list of string);
};

HASH_SIZE: con 31;
VK_APP_ID: con 1936127;
VK_PERM_NOTIFY,
VK_PERM_FRIENDS,
VK_PERM_PHOTOS,
VK_PERM_AUDIO,
VK_PERM_VIDEO,
VK_PERM_OFFERS,     # deprecated
VK_PERM_QUESTION,   # deprecated
VK_PERM_PAGES,
VK_PERM_MENU,
VK_PERM_DUMMY,      # just skip this val
VK_PERM_STATUS,
VK_PERM_NOTES,
VK_PERM_MESSAGES,
VK_PERM_WALL:       con (1 << iota);
VK_API_URL:         con "https://api.vk.com/method/";

Qroot: con big 16rfffffff;
Qfindnode, Qfindvalue, Qstore, Qping, Qstats, Qstatus, 
Qlocalstore, Qourstore, Qcontacts, Qnode: con big iota + big 16r42;
nav: ref Navigator;
navpid: int;

# vk api authorization token
authkey: string;
authuid := 17209872; # TODO: read from config
# these things keep track of all the paths in the fs
qidtopath: array of string;
pathtoqid: ref HashTable[string];
lastqid := 0;
# fs handlers
#dirhandlers: list of (Re, ref fn(path: string): list of (ref Sys->Dir, string));
#filehandlers: list of (Re, ref fn(path: string, msg: ref Tmsg, fid: ref Fid): ref Rmsg);
entryhandlers: ref HashTable[ref EntryHandler];
dircache: ref HashTable[list of ref Sys->Dir];

user: string;
stderr: ref Sys->FD;

# usefull api calling structure

ApiCall: adt {
    url: string;
    new:        fn(method: string): ref ApiCall;
    addparam:   fn(nil: self ref ApiCall, name: string): ref ApiCall;
    addvali:    fn(nil: self ref ApiCall, val: int): ref ApiCall;
    addvalb:    fn(nil: self ref ApiCall, val: big): ref ApiCall;
    addvals:    fn(nil: self ref ApiCall, val: string): ref ApiCall;
    addnextval: fn(nil: self ref ApiCall): ref ApiCall;
    call:       fn(nil: self ref ApiCall): ref JValue;
};

ApiCall.new(method: string): ref ApiCall
{
    return ref ApiCall(VK_API_URL + method + "?");
}
ApiCall.addparam(api: self ref ApiCall, name: string): ref ApiCall
{
    api.url += name + "=";
    return api;
}
ApiCall.addnextval(api: self ref ApiCall): ref ApiCall
{
    api.url += ",";
    return api;
}
ApiCall.addvali(api: self ref ApiCall, val: int): ref ApiCall
{
    return api.addvals(string val);
}
ApiCall.addvalb(api: self ref ApiCall, val: big): ref ApiCall
{
    return api.addvals(string val);
}
ApiCall.addvals(api: self ref ApiCall, val: string): ref ApiCall
{
    api.url += val + "&";
    return api;
}
ApiCall.call(api: self ref ApiCall): ref JValue
{
    api.url += "auth_token=" + authkey;
    return getresponsejson(api.url);
}

# Dirs and file helper structs

EntryHandler: adt {
    dir: ref Sys->Dir;
    path: string;
    dirhandler: ref fn(nil: self ref EntryHandler): list of ref Sys->Dir;
    filehandler: ref fn(nil: self ref EntryHandler, msg: ref Tmsg, fid: ref Fid): ref Rmsg;
};

loadmodules()
{
    sys = load Sys Sys->PATH;
    ip = load IP IP->PATH;
    if (ip == nil)
        badmodule(IP->PATH);
    keyring = load Keyring Keyring->PATH;
    if (keyring == nil)
        badmodule(Keyring->PATH);
    styx = load Styx Styx->PATH;
    if (styx == nil)
        badmodule(Styx->PATH);
    styx->init();
    styxservers = load Styxservers Styxservers->PATH;
    if (styxservers == nil)
        badmodule(Styxservers->PATH);
    styxservers->init(styx);
    nametree = load Nametree Nametree->PATH;
    if (nametree == nil)
        badmodule(Nametree->PATH);
    nametree->init();
    hashtable = load Hashtable Hashtable->PATH;
    if (hashtable == nil)
        badmodule(Hashtable->PATH);
    daytime = load Daytime Daytime->PATH;
    if (daytime == nil)
        badmodule(Daytime->PATH);
    bufio = load Bufio Bufio->PATH;
    if (bufio == nil)
        badmodule(Bufio->PATH);
    json = load JSON JSON->PATH;
    if (json == nil)
        badmodule(JSON->PATH);
    json->init(bufio);
    regex = load Regex Regex->PATH;
    if (regex == nil)
        badmodule(Regex->PATH);
    str = load String String->PATH;
    if (str == nil)
        badmodule(String->PATH);
    lists = load Lists Lists->PATH;
    if (lists == nil)
        badmodule(Lists->PATH);
}

init(nil: ref Draw->Context, args: list of string)
{
    loadmodules();

    # get some usefull things
    user = getcuruser();
    stderr = sys->fildes(2);

    # setup a pipe
    fds := array [2] of ref Sys->FD;
    if(sys->pipe(fds) < 0)
        vkfsfatal("fail:error creating pipe");

    # parse cmdline args
    arg := load Arg Arg->PATH;
    if(arg == nil)
        badmodule(Arg->PATH);
    arg->init(args);
    flags := Sys->MREPL;
    copt := 0;
    while((o := arg->opt()) != 0)
        case o {
            'a' =>  flags = Sys->MAFTER;
            'b' =>  flags = Sys->MBEFORE;
            'c' =>  copt = 1;
            'D' =>  styxservers->traceset(1);
            * =>        usage();
        }
    args = arg->argv();
    arg = nil;

    if (args == nil)
        usage();
    authkey = readfile(hd args);
    args = tl args;

    vkfslog("Starting");

    # setup all the tables
    qidtopath = array [] of {"/"};
    pathtoqid = hashtable->new(HASH_SIZE, "");
    pathtoqid.insert("/", "0");
    dircache = hashtable->new(HASH_SIZE, Blankdir :: nil);
    #dircache.insert("/", (ref dir(".", Sys->DMDIR | 8r777, big 0), nil) :: nil);

    # actual content definitions of our fs
    #dirhandlers = (re("^/$"), rootdir) :: dirhandlers;
    #filehandlers = (re(".*/pathinfo"), infofile) :: filehandlers;
    #filehandlers = (re(".*/info"), userinfofile) :: filehandlers;
    entryhandlers = hashtable->new(HASH_SIZE, ref EntryHandler(nil, "", nil, nil));
    entryhandlers.insert("/", ref EntryHandler(dir(".", 8r777, big 0), "/", rootdir, nil));

    # init the root folder
    dirhandler(big 0);

    if(len args != 1)
        usage();
    if(copt)
        flags |= Sys->MCREATE;
    mountpt := hd args;
    args = tl args;

    # setup styx servers
    navops := chan of ref Styxservers->Navop;
    (tchan, srv) := Styxserver.new(fds[0], Navigator.new(navops), big 0);
    spawn navigator(navops);

    # start server message processing
    spawn serverloop(tchan, srv);

    # mount our server somewhere
    if(sys->mount(fds[1], nil, mountpt, flags, nil) < 0)
        vkfsfatal(sys->sprint("fail:mount error:%r"));
}

# allocates a new path and returns it's qid
addpathentry(path: string): big
{
    lastqid++;
    pathtoqid.insert(path, string lastqid);
    newqidtopath := array [len qidtopath + 1] of string;
    newqidtopath[:] = qidtopath[:];
    newqidtopath[len qidtopath] = path;
    qidtopath = newqidtopath;
    return big lastqid;
}

# styx server loop
serverloop(tchan: chan of ref Styx->Tmsg, srv: ref Styxserver)
{
    for (;;) {
        gm := <-tchan;
        if (gm == nil) {
            destroy();
            exit;
        }
        e := handlemsg(gm, srv);
        if (e != nil)
            srv.reply(ref Rmsg.Error(gm.tag, e));
    }
}

filehandler(fid: ref Fid, msg: ref Tmsg): ref Rmsg
{
    curpath := qidtopath[int fid.path];
    handler := entryhandlers.find(curpath);
    if (handler != nil)
        return handler.filehandler(handler, msg, fid);
    vkfslog("No file for path " + curpath);
    return ref Rmsg.Error(msg.tag, Enotfound);
}

# handle server messages
handlemsg(gm: ref Styx->Tmsg, srv: ref Styxserver): string
{
    pick m := gm {
    Read =>
        (fid, err) := srv.canread(m);
        if(fid == nil)
            return err;

        if((fid.qtype & Sys->QTDIR) != 0) {
            # dir reads are handled by server
            srv.read(m);
            return nil;
        }

        srv.reply(filehandler(fid, gm));
    Write =>
        (fid, err) := srv.canwrite(m);
        if (fid == nil)
            return err;
        if (fid.qtype & Sys->QTDIR)
            return Eperm;

        srv.reply(filehandler(fid, gm));
    * =>
        srv.default(gm);
    }
    return nil;
}

dirhandler(qid: big): list of ref Sys->Dir
{
    curpath := qidtopath[int qid];
    handler := entryhandlers.find(curpath);
    if (handler != nil)
    {
        # fill cache
        content := handler.dirhandler(handler);
        if (dircache.find(string qid) != nil)
            dircache.delete(string qid);
        dircache.insert(curpath, content);
        return content;
    }
    vkfslog("No folder for path " + curpath);
    return nil;
}

navigator(navops: chan of ref styxservers->Navop)
{
    navpid = sys->pctl(0, nil);
    while((m := <-navops) != nil) {
        pick n := m {
            Stat =>
                curpath := qidtopath[int m.path];
                dir := findincache(curpath);
                if (dir != nil)
                    n.reply <-= (dir, nil);
                else
                    n.reply <-= (nil, Enotfound);
            Walk =>
                curpath := qidtopath[int m.path];
                # up path handling, looks awful
                if (n.name == "..")
                {
                    parent := getparentpath(curpath);
                    dir := findincache(parent);
                    if (dir != nil)
                        n.reply <-= (dir, nil);
                    else
                        n.reply <-= (nil, Enotfound);
                    break;
                }
                # ordinary dir handling
                dir := findincache(appendpath(curpath, n.name));
                if (dir != nil)
                {
                    qid := addpathentry(appendpath(curpath, n.name));
                    if (dir.qid.qtype == Sys->QTDIR)
                        dirhandler(qid); # fill the tree
                    n.reply <-= (dir, nil);
                    break;
                }
                n.reply <-= (nil, Enotfound);
            Readdir =>
                curpath := qidtopath[int m.path];
                dirs := dircache.find(curpath);
                if (dirs == nil)
                {
                    n.reply <-= (nil, Enotfound);
                    break;
                }
                for (it := dirs; it != nil; it = tl it)
                {
                    n.offset--;
                    if (n.offset >= 0)
                        continue;
                    n.reply <-= (hd it, nil);
                    n.count--;
                    if (n.count == 0)
                        break;
                }
                n.reply <-= (nil, nil);
        }
    }
}

destroy()
{
    vkfslog("Destroying...");
    # kill self
    kill(navpid, "kill");
    exit;
}

# vk fs dirs and files handlers

rootdir(path: string): list of (ref Sys->Dir, string)
{
    root: list of (ref Sys->Dir, string);
    root = (dirbypath("pathinfo",   path, 8r777), nil) :: root;
    root = (dirbypath("root",       path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("settings",   path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("stats",      path, Sys->DMDIR | 8r777), nil) :: root;
    # concat with profile dir
    for (it := profiledir(path); it != nil; it = tl it)
        root = hd it :: root;
    return root;
}

profiledir(path: string): list of (ref Sys->Dir, string)
{
    root: list of (ref Sys->Dir, string);
    root = (dirbypath("info",       path, 8r777), nil) :: root;
    root = (dirbypath("profile",    path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("audio",      path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("video",      path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("im",         path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("photos",     path, Sys->DMDIR | 8r777), nil) :: root;
    root = (dirbypath("friends",    path, Sys->DMDIR | 8r777), nil) :: root;
    return root;
}

infofile(path: string, msg: ref Tmsg, fid: ref Fid): ref Rmsg
{
    pick m := msg {
        Read =>
            return readstr(m, "hi!\ni'm here-> " + path);
    }
    return nil;
}

userinfofile(path: string, msg: ref Tmsg, fid: ref Fid): ref Rmsg
{
    pick m := msg {
        Read =>
            if (fid.data == nil || len fid.data == 0)
            {
                response := ApiCall.new("users.get").addparam("uids").addvali(authuid).
                    addparam("fields").addvals("photo_50,city,sex,bdate,contacts").call();
                fid.data = array of byte response.text();
            }
            return readbytes(m, fid.data);
    }
    return nil;
}

# vk api functions

getauthurl(): string
{
    return "https://oauth.vk.com/authorize?client_id=" + 
        string VK_APP_ID + "&scope=notify,friends,photos,audio,video," + 
        "wall,messages,docs,pages,status,notifications" + 
        "&redirect_uri=https://oauth.vk.com/blank.html&display=popup&response_type=token";
}

getpermstring(perm: big): string
{
    # TODO: implement
    return "";
}

# network functions

getresponsetext(url: string): string
{
    # open webget file
    webget := bufio->open("/chan/webget", sys->ORDWR);
    if (webget == nil) {
        vkfslog("Cannot open webget file /chan/webget");
        return "";
    }
    webget.puts("GET 0 0 " + url + " * no-cache\n");
    webget.flush();
    # parse some answer, we will get something like
    # 'OK len reqid\nresponse' or 'ERROR reqid descr'
    webget.seek(big 0, Bufio->SEEKSTART);
    status := webget.gets(' ');
    if (len status < 3 || status[:2] != "OK") {
        # skip request id
        webget.gets(' ');
        vkfslog("Webget fail: " + webget.gets('\n'));
        webget.close();
        return "";
    }
    # read response length
    length := int webget.gets(' ');
    # skip the rest of line
    webget.gets('\n');
    response := array [length] of byte;
    readbytes := webget.read(response, length);
    if (readbytes != length) {
        vkfslog("Webget read fail");
        webget.close();
        return "";
    }
    # finish everything
    webget.close();
    return string response;
}

getresponsejson(url: string): ref JValue
{
    # open webget file
    webget := bufio->open("/chan/webget", sys->ORDWR);
    if (webget == nil) {
        vkfslog("Cannot open webget file /chan/webget");
        raise "fail:can't open webget";
    }
    webget.puts("GET 0 0 " + url + " application/json no-cache\n");
    webget.flush();
    # parse some answer, we will get something like
    # 'OK len reqid\nresponse' or 'ERROR reqid descr'
    webget.seek(big 0, Bufio->SEEKSTART);
    status := webget.gets(' ');
    if (len status < 3 || status[:2] != "OK") {
        # skip request id
        webget.gets(' ');
        vkfslog("Webget fail: " + webget.gets('\n'));
        webget.close();
        raise "fail:webget fail";
    }
    # read response length
    length := int webget.gets(' ');
    # skip the rest of line
    webget.gets('\n');
    (response, err) := json->readjson(webget);
    if (response == nil) {
        vkfslog("Readjson failed: " + err);
        webget.close();
        raise "fail:readjson:" + err;
    }
    # finish everything
    webget.close();
    return response;
}

# some helper functions

re(expr: string): Re
{
    (result, err) := regex->compile(expr, 0);
    if (result == nil)
        vkfsfatal("fail:regex compile error:" + err);
    return result;
}

findincache(path: string): ref Sys->Dir
{
    parent := getparentpath(path);
    name := getentryname(path);
    dirs := dircache.find(parent);
    if (dirs == nil)
        return nil;
    # handle root differently
    if (parent == "/" && name == "/")
        return ref dir(".", Sys->DMDIR | 8r777, big 0);
    for (it := dirs; it != nil; it = tl it)
        if (hd it != nil && (hd it).name == name)
            return hd it;
    return nil;
}

appendpath(path: string, name: string): string
{
    if (path == "/")
        return path + name;
    return path + "/" + name;
}

getentryname(path: string): string
{
    if (len path < 2)
        return path;
    (parent, name) := str->splitr(path, "/");
    return name;
}

getparentpath(path: string): string
{
    if (len path < 2)
        return path;
    (parent, name) := str->splitr(path, "/");
    if (len parent > 1) # strip the last /
        parent = parent[:len parent - 1];
    return parent;
}

badmodule(p: string)
{
    sys->fprint(sys->fildes(2), "cannot load %s: %r\n", p);
    raise "fail:bad module";
}

usage()
{
    vkfslog("Authorisation url: " + getauthurl());
    vkfslog("Usage: vkfs [-a|-b|-ac|-bc] [-D] authkey mountpoint");
    vkfsfatal("fail:usage");
}

vkfslog(msg: string)
{
    sys->fprint(stderr, "%s\n", msg);
}

vkfsfatal(msg: string)
{
    # TODO: maybe we have a better way to die?
    vkfslog(msg);
    destroy();
}

kill(pid: int, how: string)
{
    fd := sys->open("#p/"+(string pid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "%s", how);
}

getcuruser(): string
{
    return readfile("/dev/user");
}

readfile(name: string): string
{
    fd := sys->open(name, Sys->OREAD);
    if (fd == nil)
        return "";
    buf := array [8192] of byte;
    readbytes := sys->read(fd, buf, len buf);
    if (readbytes <= 0)
        return "";
    return string buf[:readbytes];
}

dirbypath(name: string, path: string, perm: int): ref Sys->Dir
{
    return ref dir(name, perm, addpathentry(appendpath(path, name)));
}

Blankdir: Sys->Dir;
dir(name: string, perm: int, qid: big): Sys->Dir
{
    d := Blankdir;
    d.name = name;
    # TODO: get this right
    d.uid = user;
    d.gid = user;
    d.qid.path = qid;
    if (perm & Sys->DMDIR)
        d.qid.qtype = Sys->QTDIR;
    else
        d.qid.qtype = Sys->QTFILE;
    d.mode = perm;
    return d;
}
