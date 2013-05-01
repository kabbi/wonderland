<img src="https://raw.github.com/kabbi/wonderland/master/Cheshire-the-Cat.jpg"
 alt="Cheshire cat" title="The guide himself" align="right" />
Wonderland
==========

>“But I don’t want to go among mad people," Alice remarked.  
>"Oh, you can’t help that," said the Cat: "we’re all mad here. I’m mad. You’re mad."  
>"How do you know I’m mad?" said Alice.  
>"You must be," said the Cat "or you wouldn't have come here.”  

Welcome to the Wonderland in the middle of Inferno!  
We are the DHT-based distributed virtual filesystem based on Vita Nuova's Inferno Operating System.

## Installation
*The following steps represent installation process on Linux, if you want to run it on Mac, replace Linux with MacOSX*  

    # Set up environment variables
    export INFERNO_ROOT=$(pwd)
    export PATH=$INFERNO_ROOT/Linux/386/bin:$PATH
    export EMU=-r$INFERNO_ROOT
    # Save them for future use
    echo "export INFERNO_ROOT=$INFERNO_ROOT"                   >> ~/.bashrc
    echo "export PATH=\$INFERNO_ROOT/Linux/386/bin:\$PATH"     >> ~/.bashrc
    echo "export EMU=-r\$INFERNO_ROOT"                         >> ~/.bashrc
    
    # Configure mkconfig
    perl -i -pe 's/^ROOT=.*/ROOT=$ENV{INFERNO_ROOT}/m'  mkconfig
    perl -i -pe 's/^SYSHOST=.*/SYSHOST=Linux/m'         mkconfig
    perl -i -pe 's/^OBJTYPE=.*/OBJTYPE=386/m'           mkconfig
    
    sh makemk.sh
    mk nuke
    mk install
    mk CONF=emu-g install

## Basic Usage

##### Start Inferno:  
`emu-g`  

*We strongly suggest installing `rlwrap` and run it this way:*  
`rlwrap -asalt emu-g`  

*Or, if you want GUI, run:*  
`emu`

##### Create a brand new Wonder layer - start a bootstrap node (Hatter)
*Here and below, 127.0.0.1 and 1200[?] are the sample address and ports accordingly*  
*The only requirement is that bootstrap nodes should be directly accessible by others*

    echo > /lib/dht/neis                                              # clear the neighbours list
    mount {cheshire udp!127.0.0.1!12001 /lib/dht/neis} /wonderland    # mount it on /wonderland
    cat /wonderland/cheshire/dht/node    # gives you the id of the node - needed later for bootstrap

##### Start a new node and attach it to Wonder (Alice)
*Start a new terminal / Inferno, then:*  

    # id (AABBCCDD), address and port are the connection credentials of any open node in Wonder
    echo AABBCCDD udp!127.0.0.1!12001 >> /lib/dht/neis 
    mount {cheshire udp!127.0.0.1!12002 /lib/dht/neis} /wonderland
##### So, by now we have at least two nodes in Wonder. Let's have some fun:  
###### It's tea-time! Hatter opens a party:  
    mkdir /tmp/tea
    echo export /tmp/tea /devices/teaparty > /wonderland/cheshire/addserver 
    cd /tmp/tea
    echo "Hot tea" > teapot
###### Alice calls Cheshire and asks him to guide her to Hatter:  
    cd /wonderland/devices/teaparty
    cat teapot # Hooray! We're in!
## Disclaimer
All the code in this repository under initial commit
is owned by google code's Inferno mercurial repository.

## License
See file **NOTICE** for complete license
