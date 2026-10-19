
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def parse_ports(port_input):
    ports = set()

    for part in port_input.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(int, part.split("-", 1))
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be 1-65535")
            ports.add(port)

        if len(ports) > 4096:
            raise ValueError("Maximum 4096 unique ports per scan")

    return sorted(ports)


def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))

            if result == 0:
                return port, "OPEN"
            elif result in (111, 61, 10061):
                return port, "CLOSED"
            else:
                return port, "CLOSED / FILTERED"

    except socket.timeout:
        return port, "FILTERED / NO RESPONSE"
    except OSError:
        return port, "UNREACHABLE / NO RESPONSE"


def main():
    try:
        target = input("Target IP address: ").strip()
        ipaddress.IPv4Address(target)

        port_input = input(
            "Ports to scan (e.g. 22,80,443 or 1-1024): "
        ).strip()
        ports = parse_ports(port_input)

        if not ports:
            raise ValueError("No ports specified")

    except (ValueError, TypeError) as error:
        print(f"Invalid input: {error}")
        return

    print(f"\nScanning {target} ({len(ports)} ports)...\n")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(
            lambda port: scan_port(target, port), ports
        )

        for port, status in results:
            print(f"Port {port:5} : {status}")

    print("\nScan complete.")


if __name__ == "__main__":
    main()
