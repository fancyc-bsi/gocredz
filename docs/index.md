---
layout: default
title: Home
nav_order: 1
permalink: /
---

# GoCredz Documentation

Welcome to the documentation for gocredz. This documentation will guide you through the various features, configurations, and usage of gocredz.

## Overview
Inspired by: "https://github.com/lgandx/PCredz" - this tool aims to capture plaintext credentials and observe network communications from a live interface or existing PCAP.

## Getting started

To use gocredz, simply download the latest binary from the release tab on github: [here](https://github.com/fancyc-bsi/gocredz/releases)

- ensure you have libpcap-dev installed for packet capture.

```bash
sudo apt-get install -y libpcap-dev 
``` 

## Features
Supports capture from the following: 

- snmp
- smtp
- ftp 
- http 
- kerberos
- NTLM
- LLMNR 
- telnet

> Can either listen on a live interface or analyze an existing pcap file for credentials.

> Supply custom regex for pattern matching (useful for HTTP).

> CSV and JSON output formats

> Notify the user if LLMNR traffic is detected on the network - for future mitm attacks.  
