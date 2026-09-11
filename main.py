#!/usr/bin/env python3
"""
AI-Powered Penetration Testing Platform
Usage: python main.py <target-url> [--output-dir <dir>]
Example: python main.py https://example.com --output-dir ./reports
"""
import asyncio
import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Penetration Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com
  python main.py https://myapp.com --output-dir ./pentest-reports
  python main.py https://api.example.com --api-key sk-ant-...

IMPORTANT: Only test targets you own or have written authorization to test.
        """,
    )
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Directory to save reports (default: ./reports)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Validate target
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Check API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable not set.")
        print("Set it with: export ANTHROPIC_API_KEY=your-key-here")
        print("Or pass it with: --api-key sk-ant-...")
        sys.exit(1)

    # Import here to avoid slow startup on bad args
    from orchestrator import Orchestrator

    orchestrator = Orchestrator(
        target=target,
        output_dir=args.output_dir,
        api_key=api_key,
    )

    try:
        result = asyncio.run(orchestrator.run())
        if not result:
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
