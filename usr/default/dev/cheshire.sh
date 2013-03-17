fn c {limbo -g -o /dis/cheshire.dis /appl/cmd/cheshire.b}
fn ml {
	mount {styxmon {ch}} /wonderland
}
fn m {
	mount {ch} /wonderland
	bind /net /wonderland/cheshire/host/net
}
fn as {cat /server > cheshire/addserver}
fn ch {cheshire udp!127.0.0.1!12100 /lib/dht/neis}
fn k {kill Cheshire Nametree Styxservers Dht}
fn u {unmount /wonderland}
