# netaudit

`netaudit.py` is a standard-library network and WireGuard audit tool. It runs
read-only checks by default and can produce reports in the terminal or several
export formats.

## Run

```sh
python3 netaudit.py
sudo python3 netaudit.py
```

Run it in a terminal to open the interactive screen. Non-root runs can inspect
most connectivity but have limited access to WireGuard and firewall details.
Running with `sudo` enables those checks; repair actions still require an
explicit confirmation. Use `--readonly` to disable repairs.

The interactive flow is: wait for checks to finish, select a check and press
Enter to inspect its evidence, press `d` for diagnosis, and `e` to export. In
the export screen, toggle formats with `j` (JSON), `m` (Markdown), `t` (text),
`h` (HTML), `c` (CSV), or `b` (bundle). Press `a` to select all, `n` to clear,
`o` to choose an output folder, then Enter to write. Leave the folder blank to
use `~/netaudit_reports/<timestamp>/`. Files are created with mode `0600`; the
folder includes a SHA-256 manifest.

## Command Line

```sh
python3 netaudit.py --plain --offline
python3 netaudit.py --json --offline
python3 netaudit.py --export json,md,csv,bundle --out ./audit-report --offline
python3 netaudit.py --selftest
```

`--offline` skips the external HTTPS status request; other checks may still
make network requests. `--name HOST` selects the hostname used for DNS checks.
Reports are redacted by default; `--no-redact` disables this, so use it only
when you have reviewed the output destination and contents.

Non-interactive commands return `1` when any check reports `FAIL`, `0` when
there are no failures, and `2` for an invalid export format.