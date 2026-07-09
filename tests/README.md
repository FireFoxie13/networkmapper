# Test harness

    pip install playwright
    python3 -m playwright install chromium

Run from the directory holding azure-net-map.html:

    python3 build_scan.py && python3 run_tests.py        # 47 assertions
    python3 build_fix_scan.py && python3 build_fwlog_scan.py && python3 build_hairball.py && python3 run_fix_tests.py   # 57
    python3 build_stress_scan.py && python3 run_stress.py                                 # 5

Each build_*.py injects a synthetic payload through the real
`const EMBEDDED=null;//__NETMAP_EMBED__` marker, exactly as generate-netmap.sh does.
Console errors fail the suite; only icons/manifest.json and favicon.ico 404s are
whitelisted. If your egress proxy re-signs TLS, the browser context already sets
ignore_https_errors=True (D3 loads from cdnjs).
