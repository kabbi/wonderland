fn cr {limbo -g -o /dis/lib/rudp.dis /appl/lib/rudp.b}
fn ct {limbo -g -o /dis/rudpping.dis /appl/cmd/rudpping.b}
fn rping {rudpping udp!127.0.0.1!12200 udp!127.0.0.1!12300 -r}
fn sping {rudpping udp!127.0.0.1!12300 udp!127.0.0.1!12200 -s $1}
fn k {kill Rudp Rudpping}
