import argparse
import sys

from report.html_generator import generate_html
from report.json_generator import generate_json
from report.sarif_generator import generate_sarif

from scanners.scanner import SecurityScanner
from scanners.security_gate import security_gate


VERSION = "1.0.0"


def run_scan(
    use_gate=False,
    minimum_severity="HIGH"
):
    """
    Run the AWS security scan and generate reports.
    """

    scanner = SecurityScanner()

    findings = scanner.scan()

    # Generate reports
    json_path = generate_json(findings)
    html_path = generate_html(findings)
    sarif_path = generate_sarif(findings)

    # Display summary
    print()
    print("=" * 60)
    print("AWS SECURITY AUDIT")
    print("=" * 60)

    print(f"Account ID : {scanner.account_id}")
    print(f"Region     : {scanner.region}")
    print(f"Findings   : {len(findings)}")

    print()
    print("Reports:")
    print(f"JSON  : {json_path}")
    print(f"HTML  : {html_path}")
    print(f"SARIF : {sarif_path}")

    # Display findings
    print()
    print("Findings:")
    print("-" * 60)

    if not findings:
        print("No security findings detected.")

    else:
        for finding in findings:

            print(
                f"[{finding.severity}] "
                f"{finding.rule_id} - "
                f"{finding.title}"
            )

            if finding.resource_id:
                print(
                    f"  Resource: "
                    f"{finding.resource_id}"
                )

    # Security gate
    if use_gate:

        passed = security_gate(
            findings,
            minimum_severity
        )

        print()
        print(
            f"Security Gate "
            f"({minimum_severity}+): "
            f"{'PASSED' if passed else 'FAILED'}"
        )

        return 0 if passed else 1

    return 0


def main():

    parser = argparse.ArgumentParser(
        description="AWS Security Audit Tool"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=VERSION
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run an AWS security scan"
    )

    scan_parser.add_argument(
        "--security-gate",
        action="store_true",
        help=(
            "Fail when findings meet or exceed "
            "the selected severity"
        )
    )

    scan_parser.add_argument(
        "--minimum-severity",
        choices=[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ],
        default="HIGH",
        help="Minimum severity that causes the security gate to fail"
    )

    args = parser.parse_args()

    if args.command == "scan":

        try:

            return run_scan(
                use_gate=args.security_gate,
                minimum_severity=args.minimum_severity
            )

        except Exception as exc:

            print(
                f"Scan failed: {exc}",
                file=sys.stderr
            )

            return 2

    parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())