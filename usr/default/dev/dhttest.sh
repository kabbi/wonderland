# some useful functions
fn c {
	limbo -g -o /dis/dhttest.dis /appl/cmd/dhttest.b
	cp /dis/dhttest.sbl /appl/cmd/
}
fn d {dhttest udp!127.0.0.1!12000 -i}
fn d1 {dhttest udp!127.0.0.1!12001 -i}
fn d2 {dhttest udp!127.0.0.1!12002 -i}
# setup some buttons
sh-button addr1 'udp!127.0.0.1!12000 '
sh-button addr2 'udp!127.0.0.1!12001 '
sh-button addr3 'udp!127.0.0.1!12002 '
sh-button log log '/dev/cons
'
sh-button 'add contact' 'addcontact '
sh-button 'print' 'print
'
