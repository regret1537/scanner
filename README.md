# Vulnerability Scanner

This is a simple web application designed to scan for common vulnerabilities like SQL Injection and XSS (Cross-Site Scripting) in websites. It uses Python's Flask framework to provide a user-friendly interface, and various proof-of-concept (PoC) scripts to detect potential security issues in target URLs.

## Features

- **SQL Injection**: Scans for potential SQL Injection vulnerabilities by injecting common payloads into URL parameters.
- **XSS (Cross-Site Scripting)**: Checks for reflected XSS vulnerabilities by injecting a simple JavaScript payload into URL parameters.
- **Flask Web Application**: Provides an easy-to-use web interface to test URLs for vulnerabilities.

## Prerequisites

Before you begin, ensure that you have met the following requirements:

- Python 3.6 or later
- Git
- A virtual environment tool (e.g., `venv` or `virtualenv`)

## Installation

### Step 1: Clone the Repository

Clone this repository to your local machine using the following command:

```bash
git clone https://github.com/yourname/vuln_scanner.git
cd vuln_scanner
