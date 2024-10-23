# ORB1T

orb1t is an advanced network testing tool built to simulate high-traffic scenarios and assess the performance and robustness of network infrastructure. Developed in Python (3.12), orb1t offers comprehensive features for generating and managing TCP/UDP traffic, making it a versatile solution for stress testing and penetration testing.

With orb1t, you can simulate various types of network loads, assess server or service reliability, and analyze how networks respond under pressure. The tool leverages multi-threading for maximum throughput, allowing users to fine-tune parameters such as packet size and transmission rates.

orb1t is designed for users who need in-depth insight into network behavior during peak traffic, making it a valuable resource for network administrators, developers, and security professionals. It’s adaptable for testing a wide range of network environments and can be optimized for testing against custom targets.

Whether you’re stress-testing a local network or simulating large-scale traffic, orb1t provides the tools to measure performance, identify bottlenecks, and improve overall resilience.


# futures
Multi-threading: orb1t can send high-speed packets using multiple threads.

Customizable packets: Choose packet size, protocol (UDP/TCP), and randomize packet sending.

Error handling: orb1t handles errors efficiently for uninterrupted testing.

Comprehensive logging: Keep track of test results with detailed packet reports.

Powerful performance: Designed for maximum packet-per-second (PPS)

wifi jammer: send deauthentication packets to a specified mac address, booting the specified device offline.

arp spoofer: intercept or manipulate network traffic between devices on the same network. 
By impersonating a device's IP address, you can redirect traffic or disrupt communications.

port scanning: scan an ip adress for open and closed ports

# Installation
To install orb1t on Windows, follow these simple steps:

```bash
git clone https://github.com/your-repo/orb1t.git
cd orb1t
pip install -r requirements.txt
REM or you can run the install.bat file
```


# Configure Your Attack
1. set your target
2. Set your thread count
3. choose your method (UDP/TCP/HTTPS/ICMP)
4. set the attack time
5. randomize packets


