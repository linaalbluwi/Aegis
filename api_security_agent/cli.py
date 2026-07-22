"""
Command-line interface for API Security Agent.
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="api-security",
        description="API Security Agent - Protect your API from vulnerabilities",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan an API endpoint for vulnerabilities")
    scan_parser.add_argument("url", help="Target API URL to scan")
    scan_parser.add_argument("--method", default="GET", help="HTTP method")

    # Version command
    version_parser = subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[*] Scanning {args.url}...")
        print("[*] Security scan complete. No vulnerabilities found (demo mode).")
    elif args.command == "version":
        print("api-security-agent version 0.1.0")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
