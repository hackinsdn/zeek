# Report over the analysis of DNS tunneling detection using Zeek

Zeek is a network monitoring tool which applies a scripts framework to promote the generation of logs. With the logs generated, it is possible to obtain informations about the network and, thus, identify anomalous traffic. In this sense, this report will focus on the usage of Zeek to detect traffic related to DNS tunnelling. 

## What is DNS tunnelling

This attack is based on sending non-DNS traffic through DNS packets, and this is possible because an attacker creates a DNS server and then leads the victim to connect to it. DNS tunnelling takes advantage over the fact that some organisations do not implement security measures over their DNS traffic.

## Establishing the tunnelling

The simulation of a DNS tunnel was made on a [Mininet-Sec](https://github.com/mininet-sec/mininet-sec/?tab=readme-ov-file#mininet-sec) instance, using a pre defined topology which contains a firewall. [More information about the topology](https://github.com/13917931-project-tasks/mnsec-docs/blob/main/en/activation.md#2-iniciate-mnsec). Due to the ubuntu firewall, some commands were necessary to change the firewall configuration and make possible the establishement of the tunnel.

### Establishing the tunnel

```
mnsecx fw0 iptables -A FORWARD -d 10.0.0.2 -p udp --dport 53 -j ACCEPT

mnsecx srv2 iodined -f -c -P ChangeMe-123 10.199.199.1/24 iodine.hackinsdn.ufba.br 
```

The fist command adds a rule to the Mininet-Sec firewall allowing incoming UDP traffic on port 53 directed to the IP address 10.0.0.2 to pass through the firewall. 

The second command promotes the establishement of a DNS tunnel server in *srv2*, which is a server of the Mininet-sec topology. There are 3 iodine parameters being used:

1. -c to disable check of client IP/port on each request;
2. -f to keep running in foreground;
3. -P to define a password used for authentication.

When establishing a DNS tunnel, it is necessary to define a network whose addresses will be used to create new interfaces in the server and in the clients hosts, and these interfaces will be used to promote the communication in the DNS tunnel. Another parameter that is applied is a domain, that is used by the client to establish the tunnel. 

### Connecting the client

```
iptables -I FORWARD -i s1+ -j ACCEPT
iptables -I FORWARD -i s2+ -j ACCEPT
mnsecx o1 iodine -f -P ChangeMe-123 10.0.0.2 iodine.hackinsdn.ufba.br
```

The first 2 commands add a rule to the machine firewall allowing any traffic coming from interfaces starting with "s1" and "s2" to be forwarded, knowing that *s1 and *s2* are switches present in the Mininet-sec topology.

In the third command, a DNS tunnel client is establised in the o1 host of Mininet-Sec topology. In this sense, it is used the IP of the server, that will used by the client establish the connection through DNS requests using the domain *iodine.hackinsdn.ufba.br* and the password defined for authentication. 

In this case, the domain does not exist, however, it is possible to establish a tunnel because the server can recognize requests involving subdomains related to *iodine.hackinsdn.ufba.br* as being request to establish a tunnel. In this sense, in the command is defined that the client will send DNS requests to the IP 10.0.0.2 (which hosts the DNS tunnel server), using subdomains related to *iodine.hackinsdn.ufba.br*.

## Communication in a DNS tunnel

As previously discussed, the firt packets sent in a DNS tunnel are the ones sent by the client to establish the tunnel. They contain requests related to subdomain linked to the domain related to the server, and are sent to the IP related to the server. This traffic is recognized as being DNS normal traffic by Zeek, with a NULL type. However, the sequent packets are classified by Wireshark as being malformed or unknown, and are not detected by Zeek as being part of a DNS traffic. 

In this sense, the informations related to tunnel establishement traffic can appear in DNS protocol related Zeek logs, bu the sequent traffic no. Consequently, it was necessary to create new frameworks to detected DNS tunnel related traffic.

## Creating new frameworks in Zeek

There are 3 characteristics of DNS tunnel related packets that were used to promote its detection:

1. The high [entropy](https://www.splunk.com/en_us/blog/security/random-words-on-entropy-and-dns.html) of the subdomains used to establish the tunnel. The Shannon Entropy formula can be used to calculate how random is a subdomain.
   1.1. The calculus involves promoting a negative sum of the frequency (quantity of occurrencies of the character divided by the size of the string) of each character multiplied by its log on the base of 2.
2. The error flags bytes:
   2.1. Normal DNS related traffic flags bytes are generally "01 00", which represents stand query packet, and "84 00" or "81 80", which represents a stand query response packet with no errors;
   2.2. DNS tunnelling related packets have the flags bytes "9e 20", which represents, according to Wireshark, Unkown operation response, with no errors. However, it is possible that there is a misinterpretation made by Wireshark that makes it classify all packets as being responses.
3. The size of the packets: In normal DNS traffic, packets generally have less than 300 bytes, but in DNS tunnelling, the packets generally have an anomalous size. Certainly, that are large DNS packets related to normal traffic, but combining an anomalous size with error flags bytes can be useful to promote thedetection of packets related to DNS tunnelling.

In order to detected the DNsS tunneling related traffic, were created 2 frameworks: a script and a custom analyzer.

## Custom script

Knowing that the traffic related to the establishement of the tunnel is detected by Zeek as normal DNS traffic, the custom script was based on the event *dns_request*. One of the parameters of this function is the query related to the request. In this sense, this event was used to obtain the query and calculate its entropy, generating a log if the entropy calculated was equal or greater to 3.8.

## Custom analyzer

The custom analyzer that was developed to parse all traffic going **to** the UDP ports 53 and 5353. In this sense, it was set to identify the first 2 bytes as being the ID of the packet, the 2 sequent bytes as being the flags, and the sequent bytes where all parsed into a single unit parameter, called payload. 

