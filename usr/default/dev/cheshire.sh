# clear the 'dht neighbours' file
fn n {echo > /lib/dht/neis}
# compile cheshire
fn c {limbo -g -o /dis/cheshire.dis /appl/cmd/cheshire.b}
# mount cheshire
fn m {mount {ch} /wonderland}
# debug helper functions to add predefined server/program
fn as {cat /server > /wonderland/cheshire/addserver}
fn ap {cat /program > /wonderland/cheshire/addprogram}
# main executable, set verbose var to be more verbose
fn ch {cheshire udp!127.0.0.1!12100 /lib/dht/neis $verbose}
# shutdown helpers, should be called in that correct order
# WARNING: this will kill all the styxservers, clients, dhts and exports!
fn k {kill Cheshire Nametree Styxservers Dht Rudp Dhtfs Logfile Styx Export}
fn u {unmount /wonderland/cheshire/dht; unmount /wonderland}
