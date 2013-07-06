load expr
# Prepare some remote shell
listen tcp!127.0.0.1!${expr 9100 $machid +} {auxi/rstyxd&}
# Clear neighbours list at startup
if {~ $machid 0} {echo > /lib/dht/neis}
# Wake up cheshire!
localaddr := udp!127.0.0.1!${expr 12500 $machid +}
mount {cheshire $localaddr /lib/dht/neis} /wonderland
# Cheshire needs some time to settle
sleep 1
# Populate neighbours table
localid := `{ifs='()'; '*'=`{cat /wonderland/cheshire/dht/node}; echo $3}
echo $localid $localaddr >> /lib/dht/neis
