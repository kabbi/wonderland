implement ConsolePinger;

include "sys.m";
	sys: Sys;
include "draw.m";

# This thing prints some message in specified computer and exit
# You should specify root path in wonder in order for this to work.

ConsolePinger: module
{
	init:	fn(ctxt: ref Draw->Context, args: list of string);
};

init(ctxt: ref Draw->Context, args: list of string)
{
	# the only thing we can safely load
	sys = load Sys Sys->PATH;

	if (args == nil || tl args == nil)
		return;

	args = tl args;
	cons := sys->open(hd args + "/dev/cons", Sys->OWRITE);
	if (cons == nil)
		return;

	args = tl args;
	if (args != nil)
		sys->fprint(cons, "%s\n", hd args);
	else
		sys->fprint(cons, "Hello from console pinger!\n");
}
