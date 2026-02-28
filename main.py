"""
main.py
~~~~~~~
CryptoShield entry point.

Usage:
    python main.py

Requires a .env file with ETHERSCAN_API_KEY set.
See .env.example for reference.
"""

import sys
from colorama import Fore, Style

from cryptoshield import analyzer, reporter
from cryptoshield.logger import get_logger

log = get_logger(__name__)


def get_address() -> str:
    """
    Prompt the user for an Ethereum wallet address and validate its format.

    :returns: Validated, lowercase Ethereum address.
    :raises SystemExit: If the address format is invalid.
    """
    print(f"  {Fore.WHITE}Enter Ethereum wallet address to analyze:{Style.RESET_ALL}")
    address = input("  > ").strip()

    if not address.startswith("0x") or len(address) != 42:
        print(
            f"\n  {Fore.RED}[ERROR] Invalid address format.\n"
            f"  Ethereum addresses must start with '0x' and be 42 characters long.{Style.RESET_ALL}"
        )
        sys.exit(1)

    return address.lower()


def main() -> None:
    """Main application entry point."""
    reporter.print_banner()

    address = get_address()
    print()

    try:
        result = analyzer.run(address)
    except EnvironmentError as exc:
        print(f"\n  {Fore.RED}[ERROR] {exc}{Style.RESET_ALL}")
        sys.exit(1)

    reporter.print_report(result)

    print(f"  {Fore.WHITE}Export full report as JSON? (y/n):{Style.RESET_ALL}", end=" ")
    if input().strip().lower() == "y":
        filename = reporter.export_json(result)
        print(f"  {Fore.CYAN}📄 Report saved to: {filename}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
