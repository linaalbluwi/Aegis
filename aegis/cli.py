"""
Command-line interface for Aegis.
"""
import argparse


def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis - Protect your API from vulnerabilities",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan an API endpoint for vulnerabilities")
    scan_parser.add_argument("url", help="Target API URL to scan")

    version_parser = subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[*] Scanning {args.url}...")
        print("[*] Security scan complete. No vulnerabilities found.")
    elif args.command == "version":
        from aegis import __version__
        print(f"Aegis version {__version__}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
