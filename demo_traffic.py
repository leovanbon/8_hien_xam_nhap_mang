import argparse
import socket
import time


def send_http_payload(host: str, port: int, payload: str) -> None:
    request = (
        "GET /search HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Demo-Payload: {payload}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        sock.connect((host, port))
        sock.sendall(request.encode("utf-8"))
        try:
            sock.recv(4096)
        except TimeoutError:
            pass


def send_port_scan(host: str, start_port: int, count: int, delay: float) -> None:
    for port in range(start_port, start_port + count):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.15)
            try:
                sock.connect((host, port))
            except OSError:
                pass
        time.sleep(delay)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate safe localhost traffic for the NIDS class demo."
    )
    parser.add_argument(
        "scenario",
        choices=["sqli", "xss", "path", "port-scan"],
        help="Demo traffic scenario to run.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host.")
    parser.add_argument("--port", type=int, default=8080, help="Target TCP port.")
    parser.add_argument(
        "--count",
        type=int,
        default=12,
        help="Number of ports to try for the port-scan scenario.",
    )
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("This demo tool only targets localhost addresses.")

    if args.scenario == "sqli":
        send_http_payload(args.host, args.port, "1' UNION SELECT username,password FROM users--")
    elif args.scenario == "xss":
        send_http_payload(args.host, args.port, "<script>alert(1)</script>")
    elif args.scenario == "path":
        send_http_payload(args.host, args.port, "../../../../etc/passwd")
    elif args.scenario == "port-scan":
        send_port_scan(args.host, args.port, args.count, delay=0.05)

    print(f"Sent {args.scenario} demo traffic to {args.host}.")


if __name__ == "__main__":
    main()
