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
or `*` to select all, `o` to choose an output folder, then Enter to write.
Leave the folder blank to use `~/netaudit_reports/<timestamp>/`. Files are
created with mode `0600`; the folder includes a SHA-256 manifest.

On the main screen, press `f` to cycle through all checks, warnings/failures,
or skipped checks. Press `R` to rerun the selected check or `r` to rerun all.

## DNS Recovery

The `systemd-resolved` check reports service state but does not assume that an
inactive service caused a resolver symlink. The WireGuard check reports any
`DNS=` setting found in `wg0.conf`.

For an explicit static-resolver repair, run the TUI as root, open Actions, and
choose **Write static DNS**. Enter IPv4 or IPv6 resolver addresses, review the
confirmation, and the tool backs up the current file or symlink before writing
a regular `/etc/resolv.conf` with mode `0644`. It then attempts a lookup. It
does not mask or stop `systemd-resolved`, alter WireGuard configuration, or
restart the tunnel.

Persistence depends on the container's init setup. A systemd oneshot unit is
appropriate only when systemd is PID 1 and its bus is reachable. A
`/etc/profile.d` hook runs when login shells start; it is not a reliable
container-boot hook and may run repeatedly. Do not install both blindly.
Before masking `systemd-resolved`, verify that it is present and is actually
managing the resolver file. Review any WireGuard `DNS=` setting and back up
`wg0.conf` before changing it; restarting a full-tunnel interface can interrupt
connectivity.

## Command Line

```sh
python3 netaudit.py --plain --offline
python3 netaudit.py --json --offline
python3 netaudit.py --check 'routes,interfaces' --json --offline
python3 netaudit.py --export json,md,csv,bundle --out ./audit-report --offline
python3 netaudit.py --export 'j*,csv' --out ./audit-report --offline
python3 netaudit.py --export '*' --out ./all-formats --offline
python3 netaudit.py --compare ./audit-report/report.json --offline
python3 netaudit.py --selftest
```

`--check` accepts comma-separated check IDs or quoted wildcard patterns and
runs only the selected checks. The interface health check reports link state,
MTU, and accumulated RX/TX errors and drops. `--compare` reads a previous
netaudit JSON report and adds status and route changes to the current report.

Export patterns match format names (`json`, `md`, `txt`, `html`, `csv`,
`bundle`) and support standard shell-style `*`, `?`, and character classes.
Quote patterns so the shell does not expand them against files in the current
directory.

`--offline` skips the external HTTPS status request; other checks may still
make network requests. `--name HOST` selects the hostname used for DNS checks.
Reports are redacted by default; `--no-redact` disables this, so use it only
when you have reviewed the output destination and contents.

Non-interactive commands return `1` when any check reports `FAIL`, `0` when
there are no failures, and `2` for an invalid export format.