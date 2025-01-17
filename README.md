# gocredz

## Quick Start Usage 

```bash
Usage of ./gocredz:
  -c string
        Comma-separated capture methods. Supported options: 
            http       (tcp port 80, 8080, or 443)
            telnet     (tcp port 23)
            ftp        (tcp port 21)
            smtp       (tcp port 25, 587, or 465)
            ldap       (tcp port 389 or 636)
            snmp       (udp port 161 or 162)
            kerberos   (tcp or udp port 88)
            dhcpv6     (udp port 546 or 547)
            llmnr      (udp port 5355)
            dnsv6      (udp or tcp port 53)
            ntlm       (tcp port 445)
        (default "all")

  -d    Enable debug mode
  -f string
        PCAP file to read
  -i string
        Interface to capture on
  -json
        Enable JSON output format
  -o string
        Output file path (without extension) (default "gocredz_output")
  -r string
        Custom regex pattern - will trigger if regex pattern matches parsed traffic
  -v int
        Verbosity level
  -version
        Show version information

Examples:
    - sudo ./gocredz -i eth0 -json 
    - sudo ./gocredz -i eth0 -d 
    - sudo ./gocredz -i eth0 -c http
    - sudo ./gocredz -f network-capture.pcap
```

# Documentation

View the docs at : https://fancyc-bsi.github.io/gocredz/
