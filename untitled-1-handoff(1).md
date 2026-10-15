# Handoff --- Untitled #1 OSINT Dashboard

**Next session focus:** Add the authenticated Shodan Host provider.

## 1. Goal

Build a portfolio-worthy OSINT aggregation dashboard MVP in a **7-day
sprint**, working approximately **3--5 hours per day**.

The application performs **passive IP intelligence lookups only**. The
user writes and runs the code, with ChatGPT providing step-by-step
guidance. Learning and understanding the implementation are part of the
goal.

-   **Repository:** `untitled-1`
-   **Local path:** `C:\Dev\Active\untitled-1`

## 2. Current State

-   Windows, Python 3.14.8 (64-bit), virtual environment `.venv`.
-   Installed dependencies: `requests`, `python-dotenv`, `streamlit`,
    `pytest`.
-   **31 tests passing**, confirmed after implementing the IPinfo Lite
    and Shodan InternetDB adapters.
-   `.gitignore` has been checked: `.env`, `.venv`, and local database
    files are ignored.
-   `.env` contains real API secrets. **Never request, print, or include
    these secrets in chat or documentation.**

### Implemented or started

-   `src/panoptes/models.py` --- provider/scan result models and overall
    status calculation.
-   `src/panoptes/providers/base.py` --- abstract provider interface.
-   `src/panoptes/providers/http.py` --- shared HTTP client and
    response/error mapping.
-   `src/panoptes/indicators.py` --- IPv4/IPv6 normalization.
-   `src/panoptes/providers/ipinfo.py` --- IPinfo Lite adapter.
-   `src/panoptes/providers/shodan.py` --- Shodan InternetDB adapter.
-   Tests for models, IP validation, HTTP handling, IPinfo Lite, and
    Shodan InternetDB.

### Important files to inspect as work continues

-   `src/panoptes/providers/virustotal.py`
-   `src/panoptes/orchestrator.py` --- currently empty.
-   `src/panoptes/storage/db.py`
-   `src/panoptes/storage/schema.sql`
-   `src/panoptes/ui/app.py`
-   `tests/test_orchestrator.py`
-   `tests/test_storage.py`
-   `tests/test_indicators.py`
-   `README.md`, `ARCHITECTURE.md`, `LIMITATIONS.md`

Some of these files may be incomplete. Inspect the actual contents
before changing them.

## 3. Decisions and Constraints

-   **Frontend:** Streamlit.
-   **Language:** Python.
-   **Data sources:** Shodan Host, Shodan InternetDB, VirusTotal, and
    IPinfo Lite.
-   **Storage:** SQLite for scan history and cached provider results.
-   **Testing:** pytest, mocked HTTP responses, and saved fixtures.
-   **Configuration:** environment variables and a local `.env`; keep
    secrets out of Git.
-   Keep provider adapters independent and normalize responses into a
    shared schema.
-   If one provider fails, preserve successful results from the others.
-   Display provider status and retrieval timestamps; distinguish cached
    or stale data from fresh results.
-   Do not interpret missing fields as zero or as proof of absence.
    VirusTotal's free tier may not return port or vulnerability fields.
-   Shodan observations are historical/provider-reported intelligence,
    not proof of a live scan or a currently exploitable vulnerability.
-   Respect API quotas, especially VirusTotal's free-tier limits. Do not
    repeatedly call providers to force rate limits.
-   Prioritize practical implementation and understanding over
    collecting certifications.
-   Preserve existing code and the project name. Make small, testable
    changes instead of replacing whole files unnecessarily.

## 4. Immediate Next Steps

### Step 1 --- Implement Shodan Host

Modify `src/panoptes/providers/shodan.py` by **adding a second
adapter**, leaving `ShodanInternetDBProvider` intact.

Expected adapter:

-   Name: `shodan_host`.
-   Endpoint: `https://api.shodan.io/shodan/host/{ip}`.
-   Authentication: read `SHODAN_API_KEY` from the environment and pass
    it as the `key` query parameter.
-   Reuse the existing `HttpClient` and shared status handling.
-   Normalize supported fields such as IP address, country, ASN,
    organization, hostnames, domains, ports, and service observations.
-   Use a 24-hour cache TTL.
-   Handle a missing API key, provider errors, and unexpected payloads
    safely.
-   Do not expose the API key in error messages or logs.

### Step 2 --- Add Tests

Extend `tests/test_adapters.py` or the existing test organization to
cover:

1.  Normalization of Shodan Host fields.
2.  Successful lookup.
3.  Missing API key.
4.  Rate-limit handling.
5.  Unexpected response payload.

Run the full test suite and confirm existing InternetDB tests still
pass.

### Step 3 --- Continue the MVP

After the Shodan Host adapter is tested, review the VirusTotal adapter,
then implement orchestration, storage/cache integration, and the
Streamlit UI in manageable steps. Finish with documentation, tests, and
a reproducible portfolio demo.

## 5. Open Items and Known Gaps

-   Confirm the exact current contents of incomplete files before
    implementation.
-   Decide how to normalize Shodan's `data` banner entries into concise
    service observations without assuming fields are always present.
-   Ensure provider errors and no-data responses produce the intended
    overall scan status.
-   Complete cache expiry, refresh behavior, and stale-data handling.
-   Build the UI and end-to-end flow after provider/orchestration
    contracts are sound.
-   Complete README, architecture, limitations, and setup instructions.

## Resume Prompt

Copy and paste this into a fresh ChatGPT session:

> Continue my "Untitled #1" OSINT dashboard project from this handoff.
> The repository is `C:\Dev\Active\untitled-1`, on Windows, using Python
> 3.14.8 and an activated `.venv`. The latest confirmed test result is
> 31 passing tests.
>
> My immediate task is to add an authenticated Shodan Host adapter to
> `src/panoptes/providers/shodan.py` without replacing or breaking the
> existing Shodan InternetDB adapter. The endpoint is
> `https://api.shodan.io/shodan/host/{ip}`, with the API key read from
> `SHODAN_API_KEY` and sent as a query parameter. Then add tests for
> normalization, success, missing key, rate limits, and unexpected
> payloads.
>
> Coach me step by step. First help me inspect the relevant current
> files and identify the smallest safe change. Explain what each change
> does, let me write and run the code, and help me interpret test
> failures. Preserve my existing work; don't dump a complete application
> or overwrite files unnecessarily. Never ask me to paste API keys or
> `.env` contents. Run the full test suite after changes and verify the
> InternetDB tests remain passing. Once this adapter is done, continue
> with the next MVP component.
