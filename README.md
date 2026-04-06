SDN ARP Handler - Project 6
1. Problem Statement
In traditional networking, switches broadcast ARP requests to all ports, which can lead to unnecessary traffic. This project implements an SDN-based ARP Proxy using the POX controller. The controller intercepts ARP requests, learns host locations (IP-to-MAC mappings), and generates ARP replies directly, reducing broadcast traffic and validating secure communication within a Mininet topology.

2. Setup and Execution Steps
This project was developed on a Dell laptop server running Ubuntu on Windows.

Prerequisites
Mininet: Network emulator.

POX Controller: Python-based SDN controller (Source-based installation used for Python 3.12 compatibility).

Execution
Start the Controller:
Navigate to the pox directory and run the custom handler:

Bash
python3 pox.py arp_handler
Start the Topology:
In a separate terminal, create a single switch topology with 3 hosts:

Bash
sudo mn --topo single,3 --controller remote,ip=127.0.0.1 --mac
3. SDN Logic & Implementation
The controller logic handles PacketIn events using a match-action approach:

Match: Incoming packets are parsed to identify ARP types.

Action (Learning): The controller extracts the source IP and MAC to populate an internal arp_table.

Action (Proxying): If the destination IP is known, the controller constructs a pkt.arp.REPLY and wraps it in an Ethernet frame using ofp_packet_out to send back to the requester.

4. Test Scenarios & Functional Validation
As per the project requirements, the following scenarios demonstrate the working behavior:

Scenario 1: Normal Operation (Success)
Condition: POX controller is running arp_handler.py.

Observation: The controller logs "Learned mapping" and "Proxying ARP reply".

Result: pingall succeeds with 0% packet loss.

Proof: <img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/e4d838b8-5d5f-4b4d-a81a-4d881e55f649" />


Scenario 2: Initial Failure (Baseline)
Condition: Mininet is started without the ARP handler active.

Observation: Hosts cannot resolve ARP, resulting in "Destination Host Unreachable".

Result: pingall shows 100% dropped packets.

Proof: <img width="1366" height="768" alt="Screenshot (1064)" src="https://github.com/user-attachments/assets/6cb848ed-b469-4e3b-91a0-810d8b8c7ca5" />



5. Performance Observation
Latency: Initial pings may show higher latency as the controller learns host locations; subsequent pings are faster due to the populated ARP table.

Correctness: Validated via pingall and manual inspection of POX console logs.
