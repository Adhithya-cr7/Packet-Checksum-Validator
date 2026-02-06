# Packet Checksum Validator

## Overview
This project is a network traffic analysis tool developed in Python using the **Scapy** library. It reads packet capture files (`.pcap` or `.pcapng`), parses the headers, and automatically validates the checksums for various network protocols. 

This tool serves as a programmatic method to verify packet integrity, serving as an alternative to Wireshark's built-in validation features.

## Features
* **Multi-Protocol Support:** Validates checksums for **IP, TCP, UDP, and ICMP**.
* **TLS Detection:** Identifies TLS traffic over TCP (Port 443).
* **Automated Verification:**
    * Extracts the original checksum from the packet header.
    * Recalculates the checksum strictly based on packet data.
    * Compares both values to determine validity (`VALID` or `INVALID`).
* **Detailed Reporting:** Outputs a table showing the packet number, protocol, status, and hex values for both original and calculated checksums.

## Prerequisites
To run this tool, you need Python installed along with the Scapy library.

### Installation
```bash
pip install scapy
