import argparse
import time
from scapy.all import sr1, IP, TCP, conf

# Suppress Scapy output
conf.verb = 0

def scan_port(target, port, timeout=2):
    """
    Scans a single port on the target using a TCP SYN packet.
    Returns the status of the port (open, closed, filtered).
    """
    pkt = IP(dst=target)/TCP(dport=port, flags="S")  # SYN packet
    response = sr1(pkt, timeout=timeout, verbose=False)

    if response is None:
        return "Filtered"  # No response or ICMP unreachable
    if response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK response
            return "Open"
        elif response.getlayer(TCP).flags == 0x14:  # RST response
            return "Closed"
    return "Filtered"

def main():
    parser = argparse.ArgumentParser(description="A simple TCP SYN port scanner using Scapy.")
    parser.add_argument("target", help="Target IP address to scan.")
    parser.add_argument("--start", type=int, help="Start port number", default=1)
    parser.add_argument("--end", type=int, help="End port number", default=65535)
    parser.add_argument("--delay", type=int, help="Delay between scans in milliseconds", default=0)

    args = parser.parse_args()
    target = args.target
    start_port = args.start
    end_port = args.end
    delay = args.delay / 1000.0  # Convert milliseconds to seconds

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Start should be >= 1 and end should be <= 65535, with start <= end.")
        return

    print(f"Starting scan on {target} from port {start_port} to {end_port}...")
    try:
        for port in range(start_port, end_port + 1):
            status = scan_port(target, port)
            print(f"Port {port}: {status}")
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
