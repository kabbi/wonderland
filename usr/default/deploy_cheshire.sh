cp /n/client/appl/cmd/cheshire.b /appl/cmd/cheshire.b
cp /n/client/appl/cmd/dhttest.b /appl/cmd/dhttest.b
cp /n/client/appl/lib/dht.b /appl/lib/dht.b
cp /n/client/module/dht.m /module/dht.m
limbo -g -o /dis/lib/dht.dis /appl/lib/dht.b
limbo -g -o /dis/dhttest.dis /appl/cmd/dhttest.b
limbo -g -o /dis/cheshire.dis /appl/cmd/cheshire.b
