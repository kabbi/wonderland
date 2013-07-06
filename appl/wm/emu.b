implement NetEmu;

#
# Subject to the Lucent Public License 1.02
#

include "sys.m";
	sys: Sys;
include "draw.m";
	draw: Draw;
	Display, Image, Point, Rect, Font: import draw;
include "math.m";
	math: Math;
include "tk.m";
include "wmclient.m";
	wmclient: Wmclient;
	Window: import wmclient;
include "daytime.m";
	daytime: Daytime;
include "lists.m";
	lists: Lists;
include "env.m";
	env: Env;
include "sh.m";
	sh: Sh;
	Context: import sh;

BLINK_EXPIRE_TIME: con 250;
INSTANCE_DRAW_RADIUS: con 10;
BLINK_TIME: con 100;
START_CMD: con "run emustart.sh";
STOP_CMD: con "run emustop.sh";
CONTROL_CHAN_DIR: con "/chan";
CONTROL_CHAN_FILE: con "emuctl";

NetEmu: module
{
	init:	fn(nil: ref Draw->Context, nil: list of string);
};

BlinkItem: adt {
	color: int;
	timestamp: int;
	target: cyclic ref Instance;
};

Instance: adt {
	id: int;
	color: int;
	point: Point;

	cmd: string;
	boottime: int;
	connections: cyclic list of ref Instance;
	blinks: cyclic list of ref BlinkItem;
	killch: chan of int;

	eq: fn(a: ref Instance, b: ref Instance): int;
	boot: fn(nil: self ref Instance);
	proc: fn(nil: self ref Instance);
	kill: fn(nil: self ref Instance);
	draw: fn(nil: self ref Instance, screen: ref Image);
	blink: fn(nil: self ref Instance, target: ref Instance, color: int);
	connectTo: fn(nil: self ref Instance, target: ref Instance);
	disconnect: fn(nil: self ref Instance, target: ref Instance);
};

Instance.eq(a: ref Instance, b: ref Instance): int
{
	return a.point.eq(b.point) && (a.boottime == b.boottime);
}
Instance.boot(i: self ref Instance)
{
	spawn i.proc();
}
Instance.proc(i: self ref Instance)
{
	#procid := sys->pctl(Sys->NEWFD | Sys->NEWPGRP | Sys->FORKNS | Sys->FORKENV, nil);
	procid := sys->pctl(Sys->NEWPGRP | Sys->FORKNS | Sys->FORKENV, nil);
	env->setenv("machid", string i.id);
	sh->system(nil, START_CMD);
	<-i.killch;
	sh->system(nil, STOP_CMD);
	killgrp(procid);
}
Instance.kill(i: self ref Instance)
{
	i.killch <-= 1;
}
Instance.blink(i: self ref Instance, target: ref Instance, color: int)
{
	blink := ref BlinkItem(color, sys->millisec(), target);
	i.blinks = blink :: i.blinks;
}
Instance.draw(i: self ref Instance, screen: ref Image)
{
	screen.ellipse(translate(i.point), INSTANCE_DRAW_RADIUS, INSTANCE_DRAW_RADIUS,
		1, display.color(Draw->Magenta), ZP);
	# Draw connections
	for (it := i.connections; it != nil; it = tl it)
		screen.line(translate(i.point), translate((hd it).point),
			Draw->Endsquare, Draw->Endsquare, 0, display.color(Draw->Black), ZP);
	# Draw blinks
	for (iit := i.blinks; iit != nil; iit = tl iit)
		screen.line(translate(i.point), translate((hd iit).target.point),
			Draw->Endsquare, screen.arrow(15, 15, 4), 1, display.color((hd iit).color), ZP);
	# Remove expired blinks
	i.blinks = lists->filter(blinkexpired, i.blinks);
}
Instance.connectTo(i: self ref Instance, target: ref Instance)
{
	i.connections = target :: i.connections;
}
Instance.disconnect(i: self ref Instance, target: ref Instance)
{
	i.connections = lists->delete(target, instances);
}

instances: list of ref Instance;

display: ref Display;
font: ref Font;
fontbg: ref Image;
zoom: int;
base, disp: Point;
instanceid := 0;

dots: ref Image;
stderr: ref Sys->FD;

# Verbose levels
EERROR, EWARNING, EINFO, EDEBUG: con iota;

trace(level: int, msg: string)
{
	sys->fprint(stderr, "Emu trace [%s]: %s\n",
		daytime->time(), msg);
}

error(msg: string, ex: string)
{
	trace(EERROR, sys->sprint("Fail: %s: %r", msg));
	raise "fail:"+ex;
}

badmodule(path: string)
{
	error("bad module " + path, "bad module");
}

init(ctxt: ref Draw->Context, nil: list of string)
{
	sys = load Sys Sys->PATH;
	# Store fd to tell about errors
	stderr = sys->fildes(2);

	draw = load Draw Draw->PATH;
	if (draw == nil)
		badmodule(Draw->PATH);
	math = load Math Math->PATH;
	if (math == nil)
		badmodule(Math->PATH);
	daytime = load Daytime Daytime->PATH;
	if (daytime == nil)
		badmodule(Daytime->PATH);
	lists = load Lists Lists->PATH;
	if (lists == nil)
		badmodule(Lists->PATH);
	wmclient = load Wmclient Wmclient->PATH;
	if (wmclient == nil)
		badmodule(Wmclient->PATH);
	env = load Env Env->PATH;
	if (env == nil)
		badmodule(Env->PATH);
	sh = load Sh Sh->PATH;
	if (sh == nil)
		badmodule(Sh->PATH);

	# Some useful init
	sys->pctl(Sys->NEWPGRP, nil);
	wmclient->init();
	zoom := 1;

	w := wmclient->window(ctxt, "Network emu", Wmclient->Appl);
	display = w.display;

	# Load the font
	font = Font.open(display, "*default*");
	if (font == nil)
		error("default font loading failed", "bad font");

	# Useful pre-defined images and bgs
	fontbg = display.newimage(Rect((0, 0), (1, 1)), Draw->RGBA32, 1, Draw->Black);
	dots = display.newimage(Rect((0,0),(1,1)), Draw->CMAP8, 1, Draw->Blue);

	w.reshape(Rect((0, 0), (600, 600)));
	w.startinput("kbd" :: "ptr" :: nil);

	w.onscreen(nil);
	base = w.image.r.min;
	drawscreen(w.image);

	# Disable for better performance
	w.image.flush(Draw->Flushoff);

	trace(EDEBUG, "Init done");
	trace(EDEBUG, sys->sprint("Our rect: %s", rect2str(w.r)));
	trace(EDEBUG, sys->sprint("Our image rect: %s", rect2str(w.image.r)));

	# Control chan listener
	ctlchan := sys->file2chan(CONTROL_CHAN_DIR, CONTROL_CHAN_FILE);
	spawn ctlchanproc(ctlchan);

	# Main fps generator
	ticks := chan of int;
	spawn timer(ticks, 100);

	connectFrom, connectTo: ref Instance;
	startDrag: ref Point;
	for(;;) alt{
		ctl := <-w.ctl or ctl = <-w.ctxt.ctl =>
			if (ctl == "exit") {
				trace(EDEBUG, sys->sprint("Killing all %d running emus", len instances));
				for (it := instances; it != nil; it = tl it)
					killinstance(hd it);
				trace(EDEBUG, "Stopping NetEmu");
			}

			w.wmctl(ctl);

			# Move or size events
			if(ctl != nil && ctl[0] == '!') {
				base = w.image.r.min;
				drawscreen(w.image);
			}
		char := <-w.ctxt.kbd =>
			# Keyboard event processing
			#case char of {
			#	'+' =>

			#}
		p := <-w.ctxt.ptr =>
			# Check if it's cosumed by the title bar
			if (w.pointer(*p))
				continue;

			# We are not interested in the out-of-the-window input
			if (!w.r.contains(p.xy))
				continue;

			point := p.xy.sub(w.image.r.min);

			{
				pp := point.sub(disp);
				inst := instancebypoint(pp);
				if (inst != nil) {
					for (it := instances; it != nil; it = tl it)
						if (!Instance.eq(inst, hd it))
							(hd it).blink(inst, Draw->Green);
				}
			}

			# Adding and connection events
			if (p.buttons & 1) {
				# In this section we are working with virtual coords
				point = point.sub(disp);

				if (connectFrom == nil) {
					connectFrom = instancebypoint(point);
					if (connectFrom == nil)
						addinstance(point, "test");
				}
				else {
					targetPoint := point;
					connectTo = instancebypoint(point);
					if (connectTo != nil)
						targetPoint = connectTo.point;
					drawconnection(w.image, connectFrom.point, targetPoint);
				}
			}
			else {
				if (connectFrom != nil && connectTo != nil) {
					connectFrom.connectTo(connectTo);
				}
				connectFrom = connectTo = nil;
			}

			# Dragging the whole area
			if (p.buttons & (1 << 2)) {
				if (startDrag == nil) {
					startDrag = ref point.sub(disp);
					selectedInstance := instancebypoint(point.sub(disp));
					if (selectedInstance != nil)
						killinstance(selectedInstance);
				}
				else {
					disp = point.sub(*startDrag);
					drawscreen(w.image);
				}
			}
			else {
				startDrag = nil;
			}

		<-ticks =>
			# Redraw at fixed fps
			drawscreen(w.image);
	}
}

# Drawing functions

ZP := Point(0, 0);

drawback(screen: ref Image)
{
	screen.draw(screen.r, display.color(Draw->Grey), nil, ZP);
	screen.text(screen.r.min.add((100, 100)), fontbg, ZP, font, "Hello, graphics! :)");
}

drawscreen(screen: ref Image)
{
	drawback(screen);

	for (it := instances; it != nil; it = tl it)
		(hd it).draw(screen);

	screen.flush(Draw->Flushnow);
}

drawconnection(screen: ref Image, source, target: Point)
{
	drawscreen(screen);

	screen.line(translate(source), translate(target), Draw->Endsquare, Draw->Endsquare, 0,
		display.color(Draw->Black), ZP);

	screen.flush(Draw->Flushnow);
}

# Instance management

addinstance(point: Point, cmd: string)
{
	instance := ref Instance;
	instance.id = instanceid++;
	instance.color = Draw->Black;
	instance.killch = chan of int;
	instance.point = point;
	instance.cmd = cmd;
	instance.boot();

	for (it := instances; it != nil; it = tl it)
		instance.connectTo(hd it);

	instances = instance :: instances;
	trace(EDEBUG, sys->sprint("Added new instance at %s with id %d",
		point2str(point), instance.id));
}

killinstance(instance: ref Instance)
{
	trace(EDEBUG, sys->sprint("Killing instance id %d", instance.id));
	instance.kill();
	for (it := instances; it != nil; it = tl it)
		(hd it).disconnect(instance);
	instances = lists->delete(instance, instances);
}

# Some other threads handlers

timer(c: chan of int, ms: int)
{
	for(;;){
		sys->sleep(ms);
		c <-= 1;
	}
}

ctlchanproc(ctlchan: ref Sys->FileIO)
{
	while (1) alt {
		(offset, count, fid, rc) := <-ctlchan.read =>
			if (rc == nil)
				continue;
			rc <-= (nil, "permission denied");
		(offset, data, fid, rc) := <-ctlchan.write =>
			if (rc == nil)
				continue;
			#trace(EDEBUG, "Ctl command: " + string data);
			if (offset == 0) {
				{
					processctlcommand(string data);
				}
				exception e {
					"fail:*" =>
						rc <-= (0, e[5:]);
						continue;
				}
			}
			rc <-= (len data, nil);
	}
}

processctlcommand(data: string)
{
	#trace(EDEBUG, "Ctl chan command: " + data);
	(cmdcount, cmdlist) := sys->tokenize(data, " \n");
	if (cmdcount == 0)
		raise "fail:no command";
	cmd := hd cmdlist;
	cmdlist = tl cmdlist;
	case cmd {
		"packet" =>
			if (len cmdlist < 2)
				raise "fail:bad args";
			sourceid := int hd cmdlist;
			targetid := int hd tl cmdlist;
			color := Draw->Black;
			if (tl tl cmdlist != nil)
				color = int hd tl tl cmdlist;
			source := instancebyid(sourceid);
			target := instancebyid(targetid);
			if (source != nil && target != nil)
				source.blink(target, color);
		* =>
			raise "fail:unknown command";
	}
}

# Some utility functions

blinkexpired(b: ref BlinkItem): int
{
	now := sys->millisec();
	return ((now - b.timestamp) < BLINK_EXPIRE_TIME);
}

killgrp(gid: int)
{
    fd := sys->open("#p/"+(string gid)+"/ctl", sys->OWRITE);
    if(fd != nil)
        sys->fprint(fd, "killgrp");
}

translate(p: Point): Point
{
	p = disp.add(base.add(p));
	return p;
}

instancebypoint(point: Point): ref Instance
{
	for (it := instances; it != nil; it = tl it)
		if (dist((hd it).point, point) < INSTANCE_DRAW_RADIUS)
			return hd it;
	return nil;
}

instancebyid(id: int): ref Instance
{
	for (it := instances; it != nil; it = tl it)
		if ((hd it).id == id)
			return hd it;
	return nil;
}

dist(p1: Point, p2: Point): int
{
	p := p1.sub(p2);
	return int math->hypot(real p.x, real p.y);
}

point2str(p: Point): string
{
	return sys->sprint("(%d, %d)", p.x, p.y);
}

rect2str(r: Rect): string
{
	return sys->sprint("(%d, %d - %d, %d)", r.min.x, r.min.y, r.max.x, r.max.y);
}

irefeq(a: ref Instance, b: ref Instance): int
{
	return (a==b);
}
