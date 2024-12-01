---
layout: default
title: Usage
nav_order: 3
---

# Usage

```bash
Usage of ./gocredz:
  -c string
        Comma-separated capture methods (default "all")
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
