#!/usr/bin/env python
import sys
import json
import argparse
from pydantic.dataclasses import dataclass
from pathlib import Path
from enum import Enum
from typing import Dict


class PermissibleOutputs(Enum):
    REPDOWN = "Reportable Markdown"


@dataclass
class VulnDigestArgs:
    input: str
    output: str
    summary: bool


class VulnDigest:
    def __init__(self, config: VulnDigestArgs) -> None:
        self.config = config

    @staticmethod
    def load_dast_report(file_path: Path) -> dict:
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError as e:
            print(f"## Failed to parse JSON: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"## File not found: {file_path}")
            sys.exit(1)

    def format_to_markdown(self, report: dict) -> str:
        markdown_content = "# DAST Report\n\n"
        markdown_content += f"**Version**: {report.get('version', 'N/A')}\n"
        markdown_content += f"**Schema**: {report.get('schema', 'N/A')}\n\n"

        scan = report.get('scan', {})
        analyzer = scan.get('analyzer', {})
        scanner = scan.get('scanner', {})

        markdown_content += "## Scan Information\n\n"
        markdown_content += f"- **Analyzer**: {analyzer.get('name')} (v{analyzer.get('version')})\n"
        markdown_content += f"- **URL**: {analyzer.get('url')}\n"
        markdown_content += f"- **Vendor**: {analyzer.get('vendor', {}).get('name')}\n\n"
        markdown_content += f"- **Scanner**: {scanner.get('name')} (v{scanner.get('version')})\n"
        markdown_content += f"- **URL**: {scanner.get('url')}\n"
        markdown_content += f"- **Vendor**: {scanner.get('vendor', {}).get('name')}\n\n"
        markdown_content += f"- **Status**: {scan.get('status')}\n"
        markdown_content += f"- **Start Time**: {scan.get('start_time')}\n"
        markdown_content += f"- **End Time**: {scan.get('end_time')}\n\n"

        markdown_content += "## Messages\n\n"
        for message in scan.get('messages', []):
            markdown_content += f"- **{message.get('level', '').capitalize()}**: {message.get('value')}\n"
        markdown_content += "\n"

        markdown_content += "## Scanned Resources\n\n"
        for resource in scan.get('scanned_resources', []):
            markdown_content += f"- **{resource.get('type', '').capitalize()}**: {resource.get('url')} (Method: {resource.get('method')})\n"
        markdown_content += "\n"

        severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
        findings_by_severity: Dict[str, list] = {level: [] for level in severity_levels}
        findings_by_severity['Unknown'] = []

        for vuln in report.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown').capitalize()
            findings_by_severity.setdefault(severity, []).append(vuln)

        for level in severity_levels + ['Unknown']:
            vulns = findings_by_severity.get(level, [])
            if vulns:
                markdown_content += f"## {level} Findings ({len(vulns)})\n\n"
                for vuln in vulns:
                    markdown_content += f"### {vuln.get('id')}\n"
                    markdown_content += f"- **Severity**: {vuln.get('severity')}\n"
                    markdown_content += f"- **Description**: {vuln.get('description')}\n"
                    markdown_content += f"- **Location**: {vuln.get('location', {}).get('path')}\n"
                    markdown_content += f"- **Identifiers**:\n\n"

                    identifiers = vuln.get('identifiers', [])
                    if identifiers:
                        markdown_content += "| Name | Value |\n|------|-------|\n"
                        for ident in identifiers:
                            markdown_content += f"| {ident.get('name')} | {ident.get('value')} |\n"
                        markdown_content += "\n"
        return markdown_content

    def print_summary(self, report: dict):
        count_by_severity = {}
        for vuln in report.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown").capitalize()
            count_by_severity[severity] = count_by_severity.get(severity, 0) + 1

        print("## DAST Vulnerability Summary:")
        for sev, count in sorted(count_by_severity.items(), key=lambda x: x[0]):
            print(f"  • {sev:<8} : {count}")
        print(f"  → Total    : {sum(count_by_severity.values())}")

    def save_markdown(self, content: str, file_path: Path) -> None:
        with open(file_path, 'w') as file:
            file.write(content)

    def run(self):
        report = self.load_dast_report(Path(self.config.input))
        if self.config.summary:
            self.print_summary(report)
            return
        markdown_content = self.format_to_markdown(report)
        self.save_markdown(markdown_content, Path(self.config.output))
        print(f"## Markdown report saved to {self.config.output}")


class VulnDigestCLIWrapper:
    @staticmethod
    def build_parser():
        parser = argparse.ArgumentParser(
            prog="vulndigest",
            description="VulnDigest - A CLI tool to convert DAST JSON reports into clean, readable Markdown summaries.",
        )
        parser.add_argument("-i", "--input", type=str, required=True, help="Input JSON file path.")
        parser.add_argument("-o", "--output", type=str, help="Output markdown file path.")
        parser.add_argument("--summary", action="store_true", help="Print summary counts only, no file generated.")
        parser.add_argument("--version", action="version", version="VulnDigest 1.0")
        return parser

    def __init__(self, args):
        self.args = self.build_parser().parse_args(args[1:])
        self.config = VulnDigestArgs(**vars(self.args))
        self.vulndigest = VulnDigest(self.config)

    def execute(self):
        self.vulndigest.run()


def main():
    cli_wrapper = VulnDigestCLIWrapper(sys.argv)
    cli_wrapper.execute()


if __name__ == "__main__":
    main()