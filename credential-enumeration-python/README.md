# credenum (Python)

> Post-access credential exposure detection for Linux systems.

`credenum` is a **defensive** security-audit tool. It scans a Linux user's home
directory for credentials that are sitting exposed — SSH private keys, cloud
provider keys, browser password databases, secrets in shell history, keyrings,
Git tokens, and database/app config files — then rates each finding by how
exposed it is and prints a report. It **only reads and reports**; it never sends
anything over the network, never cracks or decrypts anything, and never touches
another machine. It maps to **MITRE ATT&CK T1552 (Unsecured Credentials)**.

## Requirements

- Python 3.8+ (tested on 3.11). **No third-party packages** — standard library only.

## Run it

From inside this folder, any of these work:

```bash
python3 -m credenum                      # scan the current user's home
python3 credenum.py                      # same, via the launcher script
./credenum.py                            # after: chmod +x credenum.py
```

### Common options

```bash
python3 -m credenum --format json                 # structured JSON instead of the box UI
python3 -m credenum --format json --output rep.json   # ...and save it to a file
python3 -m credenum --modules ssh,git,cloud       # scan only some modules
python3 -m credenum --target /home/someone        # scan a different home dir
python3 -m credenum --dry-run                      # list what WOULD be scanned, read nothing
python3 -m credenum --quiet                        # hide the banner
python3 -m credenum --verbose                      # show modules even when they found nothing
python3 -m credenum --help
```

### Exit codes

- `0` — no HIGH or CRITICAL findings.
- `1` — at least one HIGH or CRITICAL finding (so it can gate a CI pipeline).

## Layout

```
credenum/
  types.py        # data records + the Severity / Category enums
  config.py       # every path, pattern, colour, constant (the "what we look for")
  base.py         # shared helpers: permissions, safe file reads, Finding builders
  collectors/     # one file per credential category (the "where we look")
    ssh.py  cloud.py  browser.py  history.py  keyring.py  git.py  apptoken.py
  output/
    terminal.py   # ANSI box-drawing renderer
    json_report.py# JSON serializer
  runner.py       # runs each enabled collector, tallies the summary
  cli.py          # argument parsing + main()
  __main__.py     # enables `python3 -m credenum`
credenum.py       # standalone launcher
```

