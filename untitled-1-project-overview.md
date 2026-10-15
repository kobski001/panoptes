# Untitled #1 --- OSINT Intelligence Dashboard

## Overview

**Untitled #1** is a cybersecurity portfolio project: an **OSINT
dashboard that gathers and combines publicly available intelligence
about an IP address into one easy-to-understand interface**.

OSINT stands for *Open-Source Intelligence*. In cybersecurity, it means
collecting and analyzing information from publicly accessible sources to
understand an internet-facing asset's footprint and potential risks.

## What Does the Project Do?

A user enters an IP address, such as `8.8.8.8`. Rather than visiting
several intelligence websites separately, the application queries
multiple providers and combines their results into one report.

### 1. Shodan

Retrieves information about internet-facing services and observed ports,
hostnames, and other technical details. The project uses both **Shodan
Host** and **Shodan InternetDB**.

### 2. VirusTotal

Retrieves available threat-intelligence information, such as reputation,
analysis statistics, and tags.

### 3. IPinfo Lite

Adds basic network context, including country, continent, and Autonomous
System Number (ASN) information.

## How the Application Works

1.  **User enters an IP address.**
2.  **Validate and normalize the IP** --- Python handles IPv4 and IPv6
    validation.
3.  **Query intelligence providers** --- Shodan, VirusTotal, and IPinfo.
4.  **Normalize and combine results** --- handle different response
    formats, errors, and partial results.
5.  **Display the intelligence dashboard** --- Streamlit presents the
    results, while SQLite supports lookup history and caching.

The main engineering challenge isn't simply calling APIs. It's making
different providers' responses work together reliably, even when a
provider is unavailable, returns no data, or hits a rate limit.

## Why Is This a Good Cybersecurity Portfolio Project?

The project demonstrates several practical skills:

-   **Python development:** modules, classes, data structures,
    exceptions, and API integration.
-   **Networking fundamentals:** IP addresses, ports, protocols, ASNs,
    and HTTP.
-   **Security tooling:** integrating established threat-intelligence
    sources.
-   **Software engineering:** reusable provider adapters, normalized
    data models, configuration, and separation of concerns.
-   **Testing:** using pytest and mocked responses to verify success and
    failure scenarios.
-   **Data management:** SQLite, caching, expiry, and historical
    lookups.
-   **Application development:** building an interactive Streamlit
    interface and documenting the project.

These skills are transferable to entry-level SOC analyst and security
engineering roles, and can provide a foundation for later
penetration-testing work.

## Scope and Limitations

### The application will

-   Gather passive IP intelligence.
-   Combine information from multiple sources.
-   Show provider errors and partial results.
-   Cache results and keep lookup history.

### The application will not

-   Actively scan or attack a target.
-   Guarantee that an IP address is malicious or safe.
-   Assume missing data means no threat exists.
-   Prove that an observed service is currently vulnerable.

## Intended Outcome

The goal is a working, tested application that can be demonstrated
through a GitHub repository, explained during interviews, and extended
with additional intelligence sources later.

**In short:** Untitled #1 is a small, practical threat-intelligence
aggregation platform that connects computer science fundamentals with
real cybersecurity workflows.
