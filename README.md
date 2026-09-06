# CPanelScanner

<p align="center">
  <b>cPanel & WHM Service Discovery Scanner</b><br>
  Fast, concurrent and lightweight scanner written in Go.
</p>

<p align="center">
  <code>By ThePurge</code>
</p>

---

## Overview

**CPanelScanner** is a lightweight scanner written in Go for identifying exposed **cPanel** and **WHM** services through their standard network ports.

It supports individual targets, hostnames, CIDR ranges, IPv4, IPv6 and target lists while using concurrent workers for efficient scanning.

The detection engine analyzes multiple response characteristics and assigns weighted signals to improve service identification and reduce false positives.

---

## Features

* Fast concurrent scanning
* IPv4 and IPv6 support
* Single IP or hostname scanning
* CIDR range support
* Target file support
* Automatic duplicate handling
* Configurable workers
* Configurable timeout
* CIDR host limits
* cPanel detection
* WHM detection
* HTTP and HTTPS support
* TLS certificate verification
* Optional insecure TLS mode
* Redirect protection
* Weighted fingerprinting
* Confidence scoring
* Verbose output
* Report generation
* Built-in self-tests
* Graceful cancellation
* No external dependencies

---

## Supported Services

| Port   | Protocol | Service |
| ------ | -------- | ------- |
| `2082` | HTTP     | cPanel  |
| `2083` | HTTPS    | cPanel  |
| `2086` | HTTP     | WHM     |
| `2087` | HTTPS    | WHM     |

CPanelScanner does not classify a service based only on its port.

The scanner evaluates multiple indicators from HTTP responses before determining whether a target is **cPanel**, **WHM**, **unknown**, or an **error**.

---

## Detection

The fingerprinting engine evaluates signals such as:

* HTTP status
* Response headers
* Server information
* Page titles
* cPanel-specific content
* WHM-specific content
* Known service indicators
* Response paths
* Multiple weighted fingerprints

Different indicators have different strengths.

Generic references to cPanel or WHM are not automatically considered a positive detection, helping reduce false positives from unrelated web applications.

---

## Requirements

* Go installed on your system
* Network access to the targets being tested

Check your Go installation:

```bash
go version
```

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/Th3Purge/cpanelscanner.git
cd cpanelscanner
```

---

## Usage

### Run Directly From Source

You can run CPanelScanner directly without compiling it first:

```bash
go run cpanel.go -ip 192.168.1.1
```

### Single Target

```bash
go run cpanel.go -ip 192.168.1.1
```

### Verbose Mode

```bash
go run cpanel.go -ip 192.168.1.1 -v
```

Verbose mode displays additional information about individual probes, detection scores, response times and errors.

### CIDR Range

```bash
go run cpanel.go -ip 192.168.1.0/24
```

### Limit Hosts

For larger CIDR ranges:

```bash
go run cpanel.go -ip 192.168.1.0/16 -max-hosts 500
```

### Target File

```bash
go run cpanel.go -f targets.txt
```

### Increase Workers

```bash
go run cpanel.go -f targets.txt -t 50
```

### Custom Timeout

```bash
go run cpanel.go -ip 192.168.1.1 -timeout 10
```

### Save Results

```bash
go run cpanel.go -ip 192.168.1.1 -o results.txt
```

### Insecure TLS Mode

```bash
go run cpanel.go -ip 192.168.1.1 -insecure
```

### Self-Test

```bash
go run cpanel.go -selftest
```

A successful self-test ends with:

```text
all checks passed
```

---

## Building

Compile the scanner into a standalone executable:

```bash
go build -o cpanel cpanel.go
```

On Linux or macOS:

```bash
./cpanel -ip 192.168.1.1
```

On Windows PowerShell:

```powershell
.\cpanel.exe -ip 192.168.1.1
```

After compilation, the executable can be used without `go run`.

---

## Command-Line Options

| Option       | Description                                 | Default         |
| ------------ | ------------------------------------------- | --------------- |
| `-ip`        | IP address, hostname or CIDR range          | —               |
| `-f`         | File containing targets                     | —               |
| `-t`         | Number of concurrent workers                | `20`            |
| `-timeout`   | HTTP request timeout in seconds             | `6`             |
| `-o`         | Output report file                          | —               |
| `-ua`        | HTTP User-Agent                             | `cpanel/2.1.0` |
| `-max-hosts` | Maximum hosts processed from target sources | `65536`         |
| `-insecure`  | Accept invalid TLS certificates             | Disabled        |
| `-v`         | Enable verbose output                       | Disabled        |
| `-no-color`  | Disable colored terminal output             | Disabled        |
| `-selftest`  | Run internal tests                          | Disabled        |

---

## Target Files

Targets can be provided using the `-f` option.

Example:

```text
192.168.1.1
192.168.1.10
192.168.1.0/24
2001:db8::1
example.com
```

Blank lines are ignored.

Lines beginning with `#` are ignored.

Comments can also be placed after a target using `#` or `;`.

Duplicate targets are handled automatically.

---

## CIDR Scanning

CPanelScanner supports both IPv4 and IPv6 CIDR ranges.

Large ranges are processed progressively instead of unnecessarily loading the entire range into memory.

The `-max-hosts` option can be used to limit the number of hosts processed:

```bash
go run cpanel.go -ip 10.0.0.0/8 -max-hosts 1000
```

When the configured host limit is reached, the scan stops cleanly and the summary reports the truncation.

---

## TLS

HTTPS scanning is used for:

* cPanel — `2083`
* WHM — `2087`

TLS certificate verification is enabled by default.

For systems using self-signed or otherwise untrusted certificates, verification can be explicitly disabled:

```bash
go run cpanel.go -ip 192.168.1.1 -insecure
```

The `-insecure` option disables certificate verification for the entire scan.

---

## Redirect Protection

CPanelScanner restricts redirects to prevent probes from unexpectedly leaving the intended endpoint.

The scanner blocks:

* Cross-host redirects
* Cross-port redirects
* HTTPS-to-HTTP downgrades
* Redirects outside the expected endpoint

Redirect chains are also limited.

---

## Output

A scan displays information including:

* Target
* Port
* Protocol
* Result
* HTTP status
* Service
* Confidence
* Response time

Example:

```text
192.168.1.100:2083 | HTTPS | cPanel | 200 | high
192.168.1.101:2087 | HTTPS | WHM    | 200 | high
192.168.1.102:2083 | HTTPS | unknown | 404 | low
```

Connection errors are reported separately:

```text
192.168.1.1:2083 | HTTPS | error | refused
```

Reports can be saved using the `-o` option:

```bash
go run cpanel.go -ip 192.168.1.100 -o results.txt
```

---

## Verbose Output

Use `-v` to display additional information:

```bash
go run cpanel.go -ip 192.168.1.100 -v
```

Verbose output can include:

* Requested URL
* Detection score
* Detection signals
* Response duration
* Error details
* Final classification

---

## Self-Test

CPanelScanner includes an internal test suite designed to validate the scanner's core functionality.

Run:

```bash
go run cpanel.go -selftest
```

The test suite covers:

* Port mapping
* HTTP/HTTPS handling
* IPv4
* IPv6
* CIDR parsing
* CIDR boundaries
* Duplicate handling
* Host limits
* Probe estimation
* Worker dispatching
* Cancellation
* Redirect handling
* TLS configuration
* Fingerprint classification
* Confidence scoring
* Error classification
* Output formatting
* Result summaries

Successful execution:

```text
all checks passed
```

---

## Security

CPanelScanner is intended for **authorized security assessments, service discovery and administrative auditing**.

Only scan systems and networks that you own or have explicit permission to test.

This tool does not provide functionality for:

* Credential attacks
* Brute-force authentication
* Exploitation
* Access-control bypass
* Persistence
* Unauthorized access

CPanelScanner focuses on **service discovery and fingerprinting**.

---

## Author

**By ThePurge**


