Contains proof-of-concept code for the [draft-karstens-pim-ipv6-zeroconf-assignment](https://datatracker.ietf.org/doc/draft-karstens-pim-ipv6-zeroconf-assignment/) Internet Draft.

Usage:

```
mdns-zeroconf-mcast [OPTION]
Options:
  -i --intf=interface The network interface to use
  -n --name=name      The name of the application
  -g --groupid=id     32-bit group ID in hexadecimal
  -h --help           Prints help message
```

Use `iptables` to simulate a network partition:

```
iptables  -I INPUT  -p udp --dport mdns -j DROP
iptables  -I OUTPUT -p udp --dport mdns -j DROP
ip6tables -I INPUT  -p udp --dport mdns -j DROP
ip6tables -I OUTPUT -p udp --dport mdns -j DROP
```

and to repair the partition:

```
iptables  --flush
ip6tables --flush
```