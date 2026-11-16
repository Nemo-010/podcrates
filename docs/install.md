# The installer core

Each project of PodUtils publishes one installer in POSIX `sh` (the
owner's ruling "Installer"). The installer is a small part of the project
on top of one core of podcrates: `scripts/install/core.sh` and its
network part `scripts/install/core-net.sh` (the proxy, the downloader, the
download and the signature). The installer of `podlab`
(`scripts/install/podlab.sh`) is the example and the test.

## What the core does

| Step | What |
| --- | --- |
| The target | `uname -s` and `uname -m` give the target triple: musl on Linux, `x86_64-apple-darwin` and `aarch64-apple-darwin` (also under Rosetta), the `.exe` of `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` under a POSIX shell (Git Bash, MSYS2, Cygwin). Under QEMU user mode `uname -m` gives the emulated machine, which is the right file. `NAME_TARGET` sets the triple. |
| The pins | Each file has its SHA-256 and its size in the block of pins of the installer. A copy with no pins refuses to install. |
| The prefix | `--prefix DIR`, else `$XDG_BIN_HOME`, else `~/.local/bin`. A path of Windows (`C:\...`) goes through `cygpath -u`. The core makes it, writes a test program into it and runs it. A prefix that cannot run programs is refused with its reason (`noexec` from `/proc/self/mounts`). |
| The free space | `df -Pk` of the prefix against the sizes of the pins and 1 MiB. The error names the knob: `--prefix DIR` on a larger file system. The install writes no file outside the prefix. |
| The downloader | The first that a probe finds: `curl`, `wget`, `python3`, then `busybox wget` with a warning. `NAME_DOWNLOADER` sets one. `curl -q` and `wget --no-config` read no file of the user. |
| The proxy | `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `no_proxy` and `NO_PROXY` of the environment. The downloader reads them there: a credential never goes into argv or a file. The output shows the proxy with no credential. |
| The SHA-256 tool | The first that a probe finds: `sha256sum`, `shasum` (macOS), `openssl`, `busybox sha256sum`, `python3`. |
| The signature | Where `cosign` is on `PATH` (or `NAME_COSIGN=CMD`), before a download: `SHA256SUMS` and `SHA256SUMS.sigstore.json` of the release, `cosign verify-blob` with the identity `https://github.com/REPO/.github/workflows/release.yml@refs/tags/vVERSION` (`INST_WORKFLOW` changes the file name) and the issuer `https://token.actions.githubusercontent.com`; then each pin of this target, and the installer itself when it runs from a file, must agree with `SHA256SUMS`. A failure is a refusal with its reason and the output of `cosign`; no file changes. With no `cosign`, with `NAME_COSIGN=none`, or with `--offline`, one line says that the signature is not checked, and the pins check each file. `cosign` keeps its trust root in `TUF_ROOT`, else in a temporary directory of the prefix. |
| A second run | Each file in the prefix that agrees with its pin stays; the run downloads nothing and says "already installed". |
| The install | Each file goes to `PREFIX/.NAME-install.PID.FILE`, its SHA-256 must agree with its pin, it runs once with `--version` (its first line must be `NAME VERSION`), and only then does `mv` put it in place. A file in place is old or new, never half. On macOS, `curl`, `wget` and `python3` set no quarantine attribute; the core removes one (a file of a bundle from a browser). |
| A cut run | INT, TERM and HUP stop the download and remove the temporary files (exit 130, 143, 129). After a KILL, the next run removes the temporary files of a run whose PID does not run. |
| `--dry-run` | The plan; no file and no download. |
| `--offline FILE` | A bundle of a release (`.tar.gz`, or its unpacked directory): no network and no downloader. `gzip` and `tar` unpack it into the prefix. |
| `--version VERSION` | The installer holds the pins of one version; another version is refused with the name of its installer. |
| The PATH line | Printed. `--add-path FILE` adds it to FILE, once. |
| The setup and the self-check | The hooks `inst_setup PREFIX` (for example a configuration file) and `inst_selfcheck PREFIX` (the last step: a check of the program with no network, for example `doctor`). |

The text of the core follows the ruling "The text of a command line":
ASCII, no control character but the newline, ASD-STE100, no id of a work
entry. Each line starts with `NAME-install:`; the error text of a
downloader keeps only printable ASCII. The exit codes: 0 done, 1 a fault,
2 a usage error, 129, 130 and 143 a signal.

## Build the installer of a project

1. Copy `scripts/install/podlab.sh` to `scripts/install/NAME.sh` of the
   project, and set `INST_NAME` (the program), `INST_ENV` (the prefix of
   the variables: `NAME_MIRROR`, `NAME_DOWNLOADER`, `NAME_TARGET`) and
   `INST_REPO` (`OWNER/REPO` of the releases).
2. Keep the block of pins empty in the tree, and keep the block of the
   core: it includes `core.sh` and `core-net.sh` from the same directory.
3. Replace the hooks that the project needs: `inst_files TARGET EXE`
   (one line `NAME ASSET` for each file; the default is
   `NAME$EXE NAME-TARGET$EXE`), `inst_version_ok LINE`, `inst_setup
   PREFIX`, `inst_selfcheck PREFIX`.
4. Get `core.sh`, `core-net.sh` and `pins.py` of podcrates at a tag, and
   check each one by its SHA-256, as the watcher of
   `docs/session-protocol.md`.
5. In the release workflow, after the build:

   ```sh
   python3 -I pins.py sums dist ASSET...
   python3 -I pins.py stamp scripts/install/NAME.sh --version X.Y.Z --assets dist --out dist/NAME-install.sh
   python3 -I pins.py bundle dist/NAME-X.Y.Z.tar.gz NAME-X.Y.Z dist/NAME-install.sh dist/ASSET...
   (cd dist && sha256sum NAME-* > SHA256SUMS)
   ```

   In the run on the tag, sign `SHA256SUMS` keylessly with cosign (the
   job has `id-token: write`; `sigstore/cosign-installer` pinned by its
   commit):

   ```sh
   cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS
   ```

   Attach `NAME-install.sh`, the bundle, each asset, `SHA256SUMS` and
   `SHA256SUMS.sigstore.json` to the release. Each file is an asset of a
   release, never a workflow artifact. The identity of the signature is
   the release workflow at the tag: a run on a branch cannot sign.
6. Test the stamped file, not a copy: `scripts/install/test.sh` of
   podcrates shows the cases.

## The pins

`scripts/install/pins.py`:

| Command | What |
| --- | --- |
| `sums DIR FILE...` | `DIR/SHA256SUMS` of each FILE |
| `stamp INSTALLER --version X.Y.Z --assets DIR --out OUT` | OUT: the core inline, and the block of pins from `DIR/SHA256SUMS`. A file that does not agree with its line fails. The block holds `INST_VERSION`, `INST_TARGETS` (the triples in the names), and `INST_SUM_KEY` and `INST_SIZE_KEY` of each file (KEY: the name with each character that is not a letter or a digit as `_`). |
| `check INSTALLER` | The copy of the tree holds no pins and includes the core. |
| `bundle OUT.tar.gz NAME FILE...` | The offline bundle: each FILE in the directory NAME, mode 0755, the time `SOURCE_DATE_EPOCH`; the same input gives the same bytes. |

The pins are in the installer, so a mirror or a proxy cannot change a
file. `SHA256SUMS` comes the same way as the files; its signature ties it
to the release workflow at the tag. The installer cannot prove itself:
check it by hand before the first run.

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/PodUtils/podcrates/.github/workflows/release.yml@refs/tags/vVERSION \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## podlab

`release.yml` builds `podlab` for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` (static, `SOURCE_DATE_EPOCH`), stamps
`podlab-install.sh`, makes `podlab-VERSION.tar.gz`, writes `SHA256SUMS`,
and installs from the bundle twice. The run on the tag signs
`SHA256SUMS`, checks the signature with `cosign` and with the published
installer, and attaches the files to the release:

```sh
curl -fsSLO https://github.com/PodUtils/podcrates/releases/download/vVERSION/podlab-install.sh
sh podlab-install.sh
```

The self-check is `podlab list`.

## The test

```sh
sh scripts/install/test.sh [--strict] [--case NAME]...
```

It stamps the installer of `podlab` with `pins.py` (the real `podlab`
when `target/release/podlab` or `PODLAB` is there, else a program of
`sh`), serves the files from `scripts/install/mirror.py` on the loopback,
and runs: the pins; a first run; a second run that downloads nothing; a
dry run; a file that is replaced; a file that does not run; a corrupt
file; a run cut by KILL, TERM, INT and HUP; the offline bundle; no free
space; each downloader; the proxy with a credential; the PATH line; each
shell (`dash`, `bash --posix`, `busybox sh`, `sh`); the names of Windows
(`podlab.exe`, a prefix through `cygpath`, the CR of `curl`); the
signature with a stand-in of `cosign` (`scripts/install/test-cases.sh`: a
pass, a changed `SHA256SUMS`, a pin that it does not hold, no bundle, a
changed installer, no `cosign`, `PODLAB_COSIGN=none`); `podlab run` of
`small-tmp`, `noexec-tmp`, `noexec-home`, `inherited-fds`, `no-proc`,
`no-passwd-entry` and `ro-etc-ssl`; `shellcheck --shell=sh`. Each run has
a time limit (`INSTALL_TEST_LIMIT`, 30 s). With `--strict`, a skip fails:
the job `install` of `ci.yml` runs it so. A part that the OS of the host
does not have is `n/a` and does not fail: on macOS `busybox`, the labs
and `shellcheck`; under Git Bash of Windows also `dash`, `wget` and the
cut run. The job `install-os` of `nightly.yml` runs `--strict` on
`macos-15` and `windows-2025`, with the fake assets of the target of the
host. The plants `install-*` prove the guards.
