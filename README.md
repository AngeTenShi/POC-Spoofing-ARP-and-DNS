<h1>Prerequisite for use : </h1>

* Linux System / Unix with iptables 
* Python3 
* NodeJS server run with sudo to open 80 port
* mysql local server to save the data # if not nothing will append when running the website
* Python modules : scapy , netfilterqueue, time , argparse
* Same network that your victim to do the attack

<h2> Used Technologies :</h2>

* Python
* NodeJS
* HTML/CSS
* Linux tools

<h2> Warning </h2> 

If you want to change the sql creds to connect to the db with the website just change json config file

<h2>Steps to use : </h2>

* run sudo python3 list_hosts.py to list all your host on your network 
* run sudo node app.js to run your webserver local with nodejs
* run sudo python3 arpspoof.py ipvictim #to poisoin the arp cache of the victim 
* run sudo python3 dnsspoof.py and edit the dns_hosts variables to set your ip and your domain that you want to spoof 

Wait for your victim to connect on one a website specified in the dns_hosts variable and enjoy ! 

The purpose of this program is only educative i'm not responsible of your way to usage it
