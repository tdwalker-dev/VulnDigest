# DAST Report

**Version**: 1.0
**Schema**: https://dast.schema.org/v1

## Scan Information

- **Analyzer**: ZAP (v2.13.0)
- **URL**: https://www.zaproxy.org
- **Vendor**: OWASP

- **Scanner**: ZAP Scanner (v2.13.0)
- **URL**: https://www.zaproxy.org
- **Vendor**: OWASP

- **Status**: finished
- **Start Time**: 2024-04-01T12:00:00Z
- **End Time**: 2024-04-01T12:05:00Z

## Messages

- **Info**: Scan completed

## Scanned Resources

- **Url**: https://example.com (Method: GET)

## High Findings (1)

### VULN-001
- **Severity**: high
- **Description**: SQL Injection vulnerability found in login form.
- **Location**: /login
- **Identifiers**:

| Name | Value |
|------|-------|
| CWE | 89 |
| WASC | 19 |

## Low Findings (1)

### VULN-002
- **Severity**: low
- **Description**: X-Powered-By header discloses technology stack.
- **Location**: /
- **Identifiers**:

| Name | Value |
|------|-------|
| CWE | 200 |

