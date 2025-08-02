# PRODIGY_CS_05
Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

## Usage
1. Clone the repo or download the ```packet_sniffer.py``` file.
2. Run the script using python `packet_sniffer.py`.

## How it Works
* Uses `scapy's` `sniff()` to capture packets.
* Checks for IP-level protocols: TCP, UDP, and ICMP.
* Extracts and prints:
  * Timestamp
  * Source and destination IPs
  * Protocol type
  * Source and destination ports (if applicable)
  * Payload (in readable format, if possible)

## Ethical Guidelines for Use
✅ Use on your own machines or lab networks.
❌ Do not capture traffic from public Wi-Fi or others’ networks without permission.
✅ Great for learning protocol structures (TCP/IP, UDP, ICMP).
✅ Can be adapted for cybersecurity education or forensic analysis labs.

## Contributions
Feel free to contribute to the improvement of this tool by submitting pull requests or opening issues.
