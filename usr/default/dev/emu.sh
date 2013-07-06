# Compile, kill and run NetEmu
fn c {limbo -g -o /dis/wm/emu.dis /appl/wm/emu.b}
fn k {kill Emu}
fn e {wm/emu}

# Same for NetFilter, experimental /net filtering server
fn cn {limbo -g -o /dis/netfilter.dis /appl/cmd/netfilter.b}
fn kn {kill Netfilter Styxservers Styx Nametree}
fn m {netfilter $*}
fn ml {netfilter -D $*}
fn u {unmount /dev/net}
