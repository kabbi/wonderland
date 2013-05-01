fn cr {limbo -g -o /dis/lib/rudp.dis /appl/lib/rudp.b}
fn ct {limbo -g -o /dis/rudpping.dis /appl/cmd/rudpping.b}
fn c {cr;ct}
fn rping {rudpping udp!127.0.0.1!11000 udp!127.0.0.1!11001 -r}
fn sping {rudpping udp!127.0.0.1!11001 udp!127.0.0.1!11000 -s $1}
fn wping {rudpping udp!127.0.0.1!11002 udp!192.40.56.191!12000 -s $1}
fn k {kill Rudp Rudpping}
