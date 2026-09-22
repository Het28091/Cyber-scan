# Windows setup and operation

## Backend choice

This version is Windows-friendly through WSL2, not a native Win32 scanner. The original
runtime requires seccomp and Linux filesystem semantics. We preserve those checks;
no Python monkey-patch or audit hook is substituted for kernel isolation. External
scanners remain disabled. A future native Windows backend needs its own tested
process, filesystem and network isolation implementation.

## What setup changes

1. Checks `wsl.exe` and the selected distribution (Ubuntu-24.04 by default).
2. If missing and online, invokes `wsl --install --distribution ... --no-launch`.
3. Stops for a required Windows restart and initial Linux user creation. Rerun setup.
4. Verifies the kernel identifies a WSL2 backend; WSL1 is not converted automatically.
5. Installs missing Python, python3-venv and libseccomp2 in the selected distribution.
6. Creates a per-checkout environment under `~/.local/share/secaudit/<path-hash>/venv`.
7. Installs any application lockfile requirements; currently the Python lockfile is empty.
8. Runs preflight, then records the selected distribution locally.

The WSL installer may require Windows administrator rights. apt may ask for a Linux
sudo password. This is confined to initial setup, never an assessment. The script does
not edit PowerShell execution policy, disable firewalls, install a global Python,
install external scanners, download model weights or upload scan data.

If Windows blocks the downloaded PowerShell scripts, review them and use `Unblock-File`
on the two `.ps1` files as permitted by your organization's policy. No execution-policy
bypass is built into the launchers. If WSL is unavailable or disabled by policy, report
that blocker; this version has no native fallback.

## Supported entry points

| Windows | Linux | Action |
|---|---|---|
| `setup.cmd` | `bash setup.sh` | Connected prerequisite setup, venv, preflight |
| `setup.cmd -Offline` | `bash setup.sh --offline` | Provision only from installed prerequisites |
| `run.cmd doctor --config config/offline.json` | `bash run.sh doctor --config config/offline.json` | Readiness |
| `run.cmd scan --config config/offline.json` | `bash run.sh scan --config config/offline.json` | Synthetic source scan |
| `run.cmd dashboard` | `bash run.sh dashboard` | Authenticated read-only local dashboard |
| `run.cmd demo-server` | `bash run.sh demo-server` | Start the synthetic local target |
| `run.cmd test` | `bash run.sh test` | Local synthetic tests |
| `run.cmd reports` | `bash run.sh reports` | Display default output location |

All scanner arguments go through WSL as argument data, not interpolated shell code.
Windows drive-letter values for source/archive/config/scope/output/destination and
bundle verify/install paths are converted with wslpath. Prefer arguments separated
by spaces; paths inside JSON configs must use WSL/Linux syntax. Windows API-key
environment variables are not automatically imported into WSL. For API AI, set the
credential in your Linux shell and run from there; do not put it in launcher arguments.

Default outputs remain on Linux storage. If you explicitly set output to a Windows
filesystem mount, Unix mode bits alone do not establish restrictive NTFS ACLs. Use an
operator-controlled folder with suitable Windows ACLs. Do not put real reports in a
shared Downloads/Desktop directory. Symlink-race limitations of the original release
still apply; scan immutable source trees.

## Manual Windows acceptance check (not yet executed here)

1. Extract into a Windows path containing spaces.
2. Run setup and finish any WSL installation/restart/initial-user steps; rerun setup.
3. Run setup again and confirm idempotence and environment reuse.
4. Run doctor, then the synthetic source scan: expect five candidate findings.
5. Run the two-terminal web demo: expect eleven combined findings.
6. Start the dashboard and verify 401 without credentials, then sign in.
7. Disconnect public internet and rerun doctor/source demo and local-web demo.
8. Verify a Windows source path with spaces, inspect Linux-stored output from Explorer.
9. Run `run.cmd test`; record Windows, WSL, Ubuntu and Python versions.

## Official references reviewed

- https://learn.microsoft.com/en-us/windows/wsl/install
- https://learn.microsoft.com/en-us/windows/wsl/basic-commands
- https://docs.python.org/3/library/venv.html
