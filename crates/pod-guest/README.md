# pod-guest

A disposable QEMU guest on Linux. One emulator child, a per-run qcow2
overlay over a read-only base image, and a FAT16 mailbox volume that the
host and the guest both see. There is no daemon and no libvirt. Four
rules:

1. The accelerator comes from the machine profile of `pod-hostprobe`:
   `kvm` where the `full` profile holds, `tcg` where only `tcg` holds, and
   a refusal where neither holds. TCG is slower; it is not a refusal.
2. The base image is never written. A run writes to an overlay; a
   provision converts the overlay into a new standalone image with no
   backing file.
3. The mailbox is the channel of a run. By default the guest has no
   network (`-nic none`); `Plan::options` can give it one ("The options of
   a plan"). The host writes the command and a random token before the
   boot, and reads the exit code, stdout and stderr after the guest stops.
   A result with another token is refused.
4. A run that times out is stopped and reported, never `Ok`. The stop says
   if the emulator was reaped (`Stop::Confirmed`) or only signalled
   (`Stop::Attempted`).

Two flavours share the mailbox, the token, QMP, the per-run directory and
the stop:

* UEFI: q35, OVMF (code read-only, a copy of the variable store for each
  run), two NVMe disks (the overlay; the mailbox with
  `cache=writethrough`), or the mailbox on a USB stick with a removable
  medium (`MailboxBus::Usb`). A `cmd.exe` agent, which a provision boot installs
  as an `onstart` scheduled task, writes `WQREADY.TXT` when it finds the
  mailbox, runs the command in a child `cmd /c` (stdin `NUL`; an `exit` in
  the command ends the child, not the agent), writes the result and powers
  the guest off. With `WQKEEP.TXT` on the mailbox (`Mode::KeepAlive`) the
  agent keeps the guest up and polls for the next token; a last command
  with no `WQKEEP.TXT` powers the guest off. Each next command comes on a
  new mailbox medium through QMP ("The next command", below).
* DOS: FreeDOS 1.4 on `pc` with SeaBIOS and two IDE disks. The crate types
  the boot keys and two lines into the console through QMP and polls the
  mailbox for the result.

The crate also gives a guest kernel its modules: it reads the squashfs
modloop of the kernel on the host and returns the modules that the guest
needs, with their dependencies ("The modloop", below).

The crate is Linux only (`#![cfg(target_os = "linux")]`): on another
target it is empty. It reads no variable of the environment and prints
nothing. At run time it starts the emulator and `qemu-img` that the caller
names. No test needs KVM or QEMU; the five tests that start a real
emulator skip where no `qemu-system-x86_64` is on `PATH` (the KVM one also
where `/dev/kvm` does not open; the two of the warm start and the one of
the swap also where no `qemu-img` is on `PATH`).

A guest of the UEFI flavour in keep-alive mode can be saved once and
restored at each later run in place of a boot ("The warm start", below).

## API

| Item | What |
| --- | --- |
| `Settings` | `scratch_root` (the directory of the per-run directories), `scratch_prefix`, `keep` (keep each per-run directory), `marker` (the content of `WQMARK.TXT`), `oem` (the OEM name of the volume, 8 characters at most). `Settings::new(root)` gives `pod-guest-`, no keep, `pod-guest`, `PODGUEST` |
| `Plan`, `Accel`, `accel_for(Option<Profile>)` | the description of one run (emulator, accelerator, firmware, overlay, mailbox, serial log, QMP socket, memory, CPUs, more arguments); `Accel::{word, cpu}` (`kvm`/`host`, `tcg`/`max`) |
| `Options` (`plan::options`): `nic` (`Nic::None` by default, `Nic::User(UserNet { model, forwards, restrict })`), `virtio`, `media` (`Medium { kind, path, readonly, boot }`), `vnc`, `usb_tablet`, `serial_socket`, `channels` (`Channel { name, socket }`), `hyperv`, `mailbox` (`MailboxBus::{Nvme, Usb}`, `Nvme` by default); `check()`; `MAILBOX_DRIVE` (`mbox`); `Forward::{local, spec}`, `Proto`, `NicModel`, `Virtio`, `MediumKind`, `escape`, `QGA_CHANNEL`, `HYPERV_FLAGS`, `MAX_SOCKET_PATH`, `MAX_CDROMS` | the options of a full guest of the UEFI flavour ("The options of a plan") |
| `argv(&plan)`, `overlay_argv`, `convert_argv`, `plan::base_format` | the UEFI machine line with no program; `qemu-img create -f qcow2 -F FMT -b BASE`; `qemu-img convert -f qcow2 -O qcow2 OVERLAY OUT` (a new image with no backing file; `qemu-img commit` has no output file, PodUtils/podvm#277) |
| `Request`, `Mode`, `Outcome`, `mailbox(&s, agent, &request)`, `outcome(&fat16, token)`, `poll_outcome(&fat16, token)`, `next_command(&mut fat16, &request)` | the command, the token, the limit and the mode (`Once` by default; `KeepAlive` puts `WQKEEP.TXT` on the mailbox); the code, the token and the streams; the mailbox of a run; the result of a mailbox after the power-off (`None`: the guest wrote no result; another token is `Protocol`); the result of a mailbox of a guest that runs (`None` also for another token or a code that does not parse: the guest writes it at the time); the next command on a mailbox that no running guest has mounted (the result before goes, then the command and the token; `Once` removes `WQKEEP.TXT`) |
| `stage(&s, qemu_img, base, &plan, agent, &request)`, `run(&s, &plan, &request)`, `stop(&plan)` | the mailbox file and the overlay; the boot to the power-off and the result, with the error stream of the emulator in the per-run directory (a `KeepAlive` request is `Usage`: its guest does not power off); QMP `quit` |
| `provision(&s, qemu_img, base, &plan, out, &ready, wait)` | one boot that waits for a ready guest (`ready::Ready::screen(deadline)`: a screen that settles), types the installer into the console, waits up to `wait` for the power-off, then the convert into `out`; returns `SETUP.TXT`. No ready guest is a failure with the cause `ready::Unready`. Each failure after the spawn stops the emulator, also a refusal of the keys by QMP |
| `ready` | `wait(&plan, &mut child, &Ready { signs, deadline, every })` (the index of the first sign that holds), `Sign::{Marker, Serial(text), Screen { settle }}`, `Ready::screen`, `Unready::{Deadline { after, signs }, Exited { status }}` (`Timeout`, `Unavailable`), `unready(&failure)`, `Scan` (a text in a file that grows), `SETTLE`, `EVERY` ("The readiness") |
| `scratch_dir(&s, tag)`, `scratch_of(&plan)`, `cleanup(&s, &plan)`, `RunGuard::arm(&s, &plan)` | the per-run directory `PREFIX` + pid + `-TAG`, mode 0700; the directory of the mailbox; its removal (only a directory with the prefix, not with `keep`); the removal on drop |
| `Stop`, `Timeout { after, stop }`, `timeout_of(&failure)` | the end of a stopped emulator; the cause of a run at its limit |
| `emulator` | `run_steps(argv)` (a tool to its end; a failure names the program and its stderr), `spawn_emulator(&plan, args, stderr)` (a process group of its own), `stop_emulator`, `stop_with` (QMP `quit`, `SIGKILL` to the group, a bounded reap), `QUIT_WAIT`, `STOP_WAIT`. Inside the crate, `Running` holds a spawned emulator and stops it when it is dropped, so that `provision`, `run` and the warm restore leave no emulator after an early failure |
| `agent` | the file names of the protocol (`MARKER`, `GO`, `CMD`, `OUT`, `ERR`, `CODE`, `SETUP`, `READY`, `KEEP`, `AGENT_NAME`, `SETUP_NAME`, `AGENT`), `READY_TEXT`, `Mode`, `ready(&fat16)` (the agent wrote `WQREADY.TXT`), `AGENT_CMD`, `SETUP_CMD`, `command_file`, `command_from_argv`, `quote`, `Code`, `parse_code`, `nonce()`, `nonce_from(&mut Entropy)` |
| `dos` | `argv`, `stage(&s, ...)`, `run(&plan, batch, token, timeout)`, `batch_from_argv`, `DEFAULT_MEM_MIB`, `CPUS`, `DEFAULT_TIMEOUT_SECS`, the boot waits `TO_MENU_MS`, `TO_PROCEED_MS`, `TO_PROMPT_MS`, `MBOX_DRIVE`, `BAT` |
| `fat16` | `Fat16` (`new`, `with_oem`, `from_image`, `put` (an 8.3 name, or a long name of up to `MAX_LONG_NAME` = 32 characters with VFAT entries and an alias `BASIS~N.EXT`), `get` (by the 8.3 name, the alias or the long name, in any case), `remove` (the file, its clusters and the long-name entries before it; `Ok(false)`: no such file), `list` (the long name where there is one), `is_mailbox`, `image`, `volume_id`, `set_volume_id`), `checksum` (of an 8.3 alias, for its long-name entries), `format`, `format_with`, `oem_bytes`, the geometry (16 MiB behind an MBR at LBA 2048, 4 KiB clusters), `LABEL`, `OEM`, `VOLUME_ID` |
| `fetch` | `Ceiling { max_bytes, fsize }` (the ceiling of one entry), `check_declared`, `Origin` (`get(from) -> Reply`: the caller's HTTP client; `from > 0` sends `Range: bytes=FROM-`), `Reply { status, length, range, body }`, `Stream::new(reader, declared)` (an origin of one stream that does not resume), `store(&mut origin, dest, want, ceiling, tries)` (the sha256 in hex; see "The store"), `partial` (`NAME.part`), `Span`, `parse_content_range`, `Refusal` (`DeclaredTooLarge`, `OverCeiling`, `Digest`, `Size`, `Range`, `Status`, `Broken`, `Busy`; `keeps_part`), `refusal(&failure)` |
| `qmp` | `Monitor` (`connect`, `call`, `ask(body)` (the response line), `keys`, `screendump(file)`, `quit`), `send_key`, `json_text`, `json_member(line, key)` (a string member of a response), `is_event`, `response_ok`, `key(char)` (the `send-key` name and shift for a US layout), `HOLD_MS` |
| `warm` | `fingerprint(&plan, base_digest, agent)` (`Fingerprint { qemu, cpu, firmware, base, agent, machine }`, `text()`), `qemu_version`, `host_cpu(cpuinfo)`, `machine_line(&plan)`, `stage_idle(&s, qemu_img, base, &plan, agent)`, `save(&plan, &fingerprint, dir, wait)`, `idle(&fat16)`, `restore(&s, qemu_img, &plan, &request, &warm)`, `incoming_argv(&plan, dir)`, `start(&s, qemu_img, base, &plan, agent, &request, &warm) -> (Child, Start)`, `Warm { dir, fingerprint, wait }`, `Start::{Warm, Cold(Cold)}`, `Cold::{Missing, Stale { saved, now }, Failed { why }}` (`NotFound`, `Config`, `Unavailable`), `cold(&failure)`, the file names `STATE`, `ROOT`, `MAILBOX`, `VARS`, `FINGERPRINT`, `FORMAT` ("The warm start") |
| `swap` | `Swap::new(&plan, token)` (`Usage` for a mailbox that is not `MailboxBus::Usb`), `current()`, `token()`, `poll()` (the settled outcome of the current command), `next(&mut monitor, &s, agent, &request)` (a new mailbox with the next volume id in the other file, then QMP `blockdev-change-medium`; `Usage` before a settled result, `Protocol` for a refusal, and the medium stays); `settled(&fat16, token)` (the code of the token and no `WQGO.TXT`), `change_request(file)`, `other_file(&plan)` (`MAILBOX.swap`) ("The next command") |
| `modloop` | `modules(reader, kernel_release, names) -> ModuleSet` (`release`, `modules`: each `Module { path, name, bytes }` in load order, `builtin`, `dep`, `size()`), `Fault`, `fault(&failure)`, `MAX_SET`, `RELEASE_DIRS` |
| `squashfs` | `Image::open(reader)` (`superblock`, `root`, `inode(reference)`, `entries(&dir)`, `lookup(path)`, `file_at(path)`, `read(&file)`, `ids`, `export(number)`), `Superblock::parse`, `Compressor`, `Inode`, `Kind`, `Dir`, `File`, `Entry`, `listing(bytes)`, `Fault`, `fault(&failure)`, the ceilings `MAX_FILE`, `MAX_LISTING`, `MAX_LINK` |

Each failure is a `pod_core::Failure` at `Stage::Host`. A failure of I/O
keeps its cause, with the text `PATH: CAUSE`. The classes: `Timeout` (a run
at its limit, with the cause `Timeout`; a QMP socket that did not appear),
`Policy` (a ceiling of the store, with the cause `Refusal`), `TempFail` (a
store that broke on each try, or whose partial file another store holds),
`NotFound` and `Refused` (a status `404` or `410`, `401` or `403` of the
origin of a store), `Protocol` (a
digest that is not the pinned one, a size or a range of the origin that does
not agree, another status, a result that does not parse or has
another token, a guest that powered off with no result, a QMP refusal),
`Usage` (a name that is not 8.3, an OEM name that does not fit, a character
with no key, an empty argv), `Unavailable` (a tool that failed, a full
volume, no random bytes, a closed QMP connection), and the class of the I/O
kind.

A long name (Windows Setup reads `autounattend.xml` from the root of a
USB medium) goes in VFAT long-name entries before an 8.3 alias: the last
part first with the bit `0x40`, 13 UCS-2 units in each entry, a NUL and
then `0xFFFF` after the name, and the checksum of the alias in each entry.
The alias is the upper-case name with no space and no dot but the last,
cut to 6 characters, `~N` with the first `N` that no file has, and 3
characters of the extension (`AUTOUN~1.XML`, then `AUTOUN~2.XML`). mtools
writes the same aliases and checksums, and reads the long names back. The
reader takes a long name only for a whole chain in order with the checksum
of the 8.3 entry after it; else it shows the 8.3 name. A name of more than
32 characters, a control character, one of `"*/:<>?\|`, a character out of
UCS-2, or a space or a dot at the end is `Usage`.

The FAT16 reader does not trust the volume that the guest wrote: a cluster
outside the volume, a loop in a chain, or a size that the chain does not
hold reads as no file.

## The readiness

`ready::wait` replaces a fixed sleep. It polls the signs each `every` until
one holds, the emulator exits (`Unready::Exited`, `Unavailable`), or the
deadline comes (`Unready::Deadline`, `Timeout`, with each sign in its
text). It does not stop the emulator.

| Sign | Holds when |
| --- | --- |
| `Marker` | the mailbox file of the plan holds `WQREADY.TXT` with `WQREADY` (the agent of a provisioned image) |
| `Serial(text)` | the serial log of the plan holds `text`; each poll reads at most 1 MiB of new bytes and keeps the end of the last ones, so that a text that two polls cut is found |
| `Screen { settle }` | the sha256 of a QMP `screendump` changed after the first dump and then stayed the same for `settle`; the dump is `screen.ppm` beside the QMP socket, removed after each read |

A sign that cannot be read (no QMP socket, no log at the time of a poll)
does not hold. The provision boot installs the agent, so it waits for the
screen. The tests
run against stand-ins: a mailbox file, a log that grows, a QMP server on a
Unix socket that gives a script of frames, `sleep` and `sh -c 'exit 3'` as
the emulator, and a provision whose emulator exits at once.

## The warm start

`warm` saves a booted guest in keep-alive mode once, and each later run
restores it in place of a boot (PodUtils/podvm#350, item 7).

1. Make the state: `stage_idle` (the overlay, and a mailbox with the agent
   and `WQKEEP.TXT` but no token), the start of the emulator, `ready::wait`
   for `Sign::Marker`, then `save(&plan, &fingerprint(..)?, dir, wait)`.
   The save refuses a guest that is not an idle agent (`idle`: no
   `WQREADY.TXT`, no `WQKEEP.TXT`, or a `WQGO.TXT`), sends QMP `stop`,
   `migrate` to `file:DIR/state.bin`, copies the overlay, the mailbox and
   the variable store, writes `fingerprint.txt` last, and sends `cont`: the
   guest goes on. The files go to `DIR.part` and get the name `DIR` at the
   end; a failed save keeps the state before it.
2. Each run: `start` restores the state, or boots cold with `stage` when
   the state is missing, stale or does not load. Both paths end with a
   running emulator and the command of the request on the mailbox.

| Step of the restore | What |
| --- | --- |
| The fingerprint | `fingerprint.txt` must be the text of `Warm::fingerprint`, line for line; else `Cold::Stale` with the first line that differs |
| The disk | a thin qcow2 overlay over `DIR/root.qcow2` at `Plan::root`; the saved overlay stays as it is |
| The mailbox | the saved one, with the next command and token (`next_command`), written before the emulator starts |
| The variable store | the saved one at `Plan::firmware_vars`; the store of the caller comes back when the load fails |
| The emulator | the machine line, then `-incoming file:DIR/state.bin`; `query-status` is `inmigrate`, then `paused`, then `cont` |

| Input of the fingerprint | Value |
| --- | --- |
| `qemu` | the first line of `EMULATOR --version`, with the build of the package |
| `cpu` | `tcg`; under KVM `host` and the sha256 of the vendor, family, model, model name, stepping and flags of the first processor (`-cpu host`) |
| `firmware` | the sha256 of the firmware code |
| `base` | the digest of the base that the caller pinned (empty is `Usage`) |
| `agent` | the sha256 of the agent |
| `machine` | `argv(&plan)` with each path of a run as a fixed name (`ROOT`, `MAILBOX`, `VARS`, `QMP`, `MEDIUM0.vhdx`, ...); the memory, the CPUs, the accelerator, the options and the arguments of the caller stay |

A wrong or stale state boots cold; it never gives the answer of another
guest. An emulator that cannot migrate a device is `Unavailable` with its
reasons (`query-migrate` `blocked-reasons`), before the guest stops: QEMU
8.2 refuses the NVMe disks of the plan line, and podvm measures QEMU 11. A
save that does not end within `wait` is cancelled (`Timeout`). The path of
the state is UTF-8 with no comma (the `file:` URI), and the overlay names
its base by an absolute path (the qcow2 head is read): the copy is in
another directory. The command of a restore goes onto the saved mailbox
before the emulator starts; the restored guest has that mailbox in its
cache, so the agent may not see it (T-602, call C543).

## The next command

A guest in keep-alive mode gets each next command on a new medium of a
USB mailbox (`MailboxBus::Usb`), never by a write into the image that it
has mounted (T-602, calls C542 to C544):

1. `Swap::poll` waits for the settled result of the command before: its
   code with the token and no `WQGO.TXT` (the agent deletes the token
   after the code; a swap before the delete lets the agent delete the new
   token).
2. `Swap::next` writes a new mailbox with the next command and the next
   volume id into the other file (`MAILBOX` and `MAILBOX.swap` in turn),
   and sends `blockdev-change-medium` for the drive `mbox`.
3. The emulator reports a unit attention at the next access of the guest.
   The disk class driver marks the device for a verify; FastFAT reads the
   boot sector, finds another volume id, drops its cache with no flush, and
   mounts the new volume at the same drive letter. The agent writes
   `WQREADY.TXT` in each poll, so that access comes also when Windows does
   not poll the drive; a poll that does not find the mailbox looks for it
   again and does not end the agent.

A write into the image of a mounted mailbox does not reach the agent:
Windows reads the directory of a mounted FAT volume from its cache, and
on a fixed disk nothing tells it that the disk changed. The guest also
writes its cached sectors over the files of the host.

## The options of a plan

`Plan::options` (`Options::default()`: the mailbox run) adds to the line
of the UEFI flavour. The DOS flavour does not read them.

| Option | Arguments |
| --- | --- |
| `nic: Nic::User(UserNet { model, forwards, restrict })` | `-nic user,model=e1000e` (or `virtio-net-pci`)`[,restrict=on],hostfwd=tcp:127.0.0.1:HOST-:GUEST...` in place of `-nic none`; `Forward::local` listens on the loopback of the host |
| `virtio: [Rng, Balloon, Keyboard, Tablet]` | `-device virtio-rng-pci` (and so on), each one time |
| `media: [Medium { kind: Cdrom, .. }]` | `-drive if=none,id=cdN,media=cdrom,readonly=on,format=raw,file=PATH`, `-device ide-cd,drive=cdN,bus=ide.N`; at most 6 (the AHCI ports of q35) |
| `media: [Medium { kind: Usb, .. }]` | `-device qemu-xhci,id=xhci` one time, `-drive if=none,id=usbN,format=FMT[,readonly=on],file=PATH` (`FMT` from the name, `plan::base_format`), `-device usb-storage,bus=xhci.0,drive=usbN,removable=on` |
| `Medium::boot` | `,bootindex=0` on the device; at most one medium |
| `vnc: Some(SOCKET)` | `-vnc unix:SOCKET`; `-display none` stays |
| `usb_tablet: true` | `-device usb-tablet,bus=xhci.0` (an absolute pointer that Windows knows with no driver) |
| `serial_socket: Some(SOCKET)` | `-chardev socket,id=serial0,path=SOCKET,server=on,wait=off,logfile=SERIAL,logappend=on`, `-serial chardev:serial0` in place of `-serial file:SERIAL` |
| `channels: [Channel { name, socket }]` | `-device virtio-serial-pci,id=vser` one time, `-chardev socket,id=chanN,path=SOCKET,server=on,wait=off`, `-device virtserialport,bus=vser.0,chardev=chanN,name=NAME` (`QGA_CHANNEL` for the guest agent) |
| `hyperv: true` | `-cpu host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_vpindex,hv_runtime,hv_synic,hv_stimer,hv_reset,hv_frequencies,hv_time,hv_tlbflush,hv_ipi` under KVM; under TCG the CPU stays `max` |

`Options::check()` refuses with `Usage`: a port 0, one port of the host
forwarded two times for one protocol and address, a socket path that is
empty, longer than 107 bytes or has a NUL, a medium with no path, more
than 6 CD-ROMs, two media that boot first, a virtio device two times, and
a channel name that is empty, has a byte other than ASCII letters, digits,
`.`, `_` and `-`, or comes two times. The start of the emulator calls it.
A comma in a path of an option list (`-drive`, `-chardev`, `-vnc`) is
written as two commas.

## The store

`fetch::store(&mut origin, dest, want, ceiling, tries)` writes the object
of the caller's HTTP client to `dest`:

* The bytes go to `NAME.part` beside `dest`, under an exclusive lock
  (`Refusal::Busy` for a second store). `dest` gets its name only after
  the size and the sha256 match.
* A break (an error of the origin, a body that ends before its declared
  size, a status `408`, `429` or `5xx`) takes one of `tries` and resumes
  with `Range: bytes=N-`. A `206` must start at `N`, and its
  `Content-Length` must be the size of its `Content-Range`
  (`Refusal::Range`). A `200` starts the file again from zero. A `416`
  with the size of the file (`bytes */SIZE`) is a whole file.
* The size of the object comes from `Content-Length` of a `200` or the
  total of a `Content-Range`. It must stay the same in each answer, and a
  body must not pass it (`Refusal::Size`). The ceiling of the entry holds
  for the declared size and for the bytes that come.
* A partial file of an earlier call is resumed only when `want` pins the
  digest: with no pin, a resume can join two versions of the object.
* A refusal of the bytes (a ceiling, a size, a range, a digest) removes the
  partial file. A break on the last try (`Refusal::Broken`, `TempFail`) and
  another status keep it, so that a later call resumes. A partial file with
  no byte goes.

The caller adds the check of free disk, `RLIMIT_FSIZE` (in `Ceiling`) and
the progress line.

## The modloop

A distribution ships the modules of its kernel as a squashfs image beside
the kernel (Alpine: `boot/modloop-virt`, xz, blocks of 128 KiB). When
`squashfs.ko` is in that image only, the guest cannot mount it. The host
calls `modloop::modules(File::open(path)?, "6.12.115-0-virt", ["tun",
"wireguard"])` and puts the set into the initramfs or a second disk of the
guest: each `Module` under its `path`, and `dep` as `modules.dep`.

* The set: each name, and each dependency of `modules.dep`, each one time,
  in load order (each dependency before its dependents; the dependencies
  of a line from its end, as modprobe loads them). `-` and `_` are the
  same in a name, as in kmod. A name of `modules.builtin` goes into
  `builtin` and needs no file. A name that is neither is
  `Fault::Unknown(name)`, class `NotFound`. A dependency loop, a line with
  no colon, a second line of one module, a path that is absolute or has
  `.` or `..`, and a file of the release that is not UTF-8 text are faults.
  The walk keeps a stack of its own.
* The release: `modules/RELEASE` (a modloop), else `lib/modules/RELEASE`
  (a root file system). Each module file is copied as it is: `.ko`, or `.ko.gz`,
  `.ko.xz`, `.ko.zst` for the guest's kmod.
* The input is a `Read + Seek`. The reader reads the superblock, the
  tables that a call needs, and the blocks of `modules.dep`,
  `modules.builtin` and of each module, not the whole image (2.2 MB of
  modules from the 21 MB modloop of Alpine 3.22.8).

The squashfs reader is for the read path only. It takes squashfs 4.0
with xz (`xz4rust`, Rust with no unsafe code): LZMA2, with or without a
BCJ filter (x86, which mksquashfs puts on some blocks of executable code;
also ARM, ARM64, ARM-Thumb, PowerPC, IA-64, SPARC and RISC-V). Each stream is one block, with a crc32 check, and decodes
to the length that its table gives; bytes after its end are a fault, as in
the kernel. The dictionary is the one of the compressor options (2^n or
3 × 2^n, at most the block size), else the block size: a stream that asks
for more is a fault, not an allocation. A stored block needs no decoder,
so an image of another compressor reads as far as its blocks are stored.
Links are not followed; xattrs are not read.

The reader trusts nothing in the image: each offset and each size is
checked against `bytes_used`, a name of a listing is one part of a path,
and a ceiling holds before each allocation (a file 64 MiB, a listing 16
MiB, a link 4 KiB, the cache of metadata 8 MiB, a set 256 MiB). Each
failure is a `pod_core::Failure` with a cause `squashfs::Fault` or
`modloop::Fault`: `NotFound` for a path, a release or a name that is not
there, `Unsupported` for a version or a compressor, `Policy` for a
ceiling, `Usage` for a release that is not one part of a path, `Protocol`
for the rest.

## Parity

Against podvm `crates/podvm-windows` at `6cd3442`:

| Capability of podvm | Here |
| --- | --- |
| [x] `Plan`, `Accel`, `accel_for`, `argv`, `base_format`, `overlay_argv`, `commit_argv` | `plan`, the same; `commit_argv` is `convert_argv` (T-266) |
| [x] `Request`, `Outcome`, `mailbox`, `outcome`, `stage`, `run`, `stop`, `provision` | the same, with `&Settings` first where a name or a place is used |
| [x] `Stop` and its text; `Error::Timeout(d, stop)` | `Timeout { after, stop }` in the chain of a `Failure` (`timeout_of`); the text is the same |
| [x] `Error::{NoEmulator, Io, BadResult}` | `Failure` with the same text (`NoAcceleration` was not used) |
| [x] The per-run directory, `scratch_of`, `cleanup`, `RunGuard`, `SCRATCH_PREFIX` | `Settings::{scratch_root, scratch_prefix}`; `RunGuard` keeps a copy of the settings |
| [x] `PODVM_WINDOWS_KEEP`, `XDG_RUNTIME_DIR` | `Settings::keep`, `Settings::scratch_root` (podvm reads the variables) |
| [x] The marker `podvm` (`podvm-dos` for DOS), the OEM name `PODVM` | `Settings::{marker, oem}` |
| [x] `base_cache`, `dos::base_cache` (`PODVM_WINDOWS_BASE`, `PODVM_DOS_BASE`, `~/.local/share/podvm/windows/`) | stay in podvm |
| [x] `cap_status` (docker's 0 to 124) | stays in podvm |
| [x] The emulator in a process group; QMP `quit`, `SIGKILL` to the group, a bounded reap; the error stream in a file | `emulator` (public now) |
| [x] `agent` (the scripts, the names, `command_file`, `command_from_argv`, `quote`, `parse_code`, `nonce`) | the same; `nonce` gives a `Result` and takes `pod_core::entropy` |
| [x] `dos` (the machine line, the stage, the boot keys, the typed lines, the poll) | the same; a line with a character that has no key is refused before the first key (podvm typed the part before it) |
| [x] `fat16` | the same; `put` gives a `Failure`; the OEM name is a setting; a chain that leaves the volume, loops or does not hold its size reads as `None` (podvm read past the image and panicked) |
| [x] `fetch` (`Ceiling`, `check_declared`, `store`, `FetchError`) | `FetchError` is the cause `Refusal` of a `Failure`; `store` takes an `Origin` (`Stream` for one reader) and resumes by Range (PodUtils/podvm#350) |
| [x] `qmp` | the same; `keys` of `lib.rs` is `qmp::key` |
| [x] The tests: 60 unit tests | 58 with their names; the tests of `base_cache` and `cap_status` stay in podvm; 7 new |

## Adoption map (podvm)

| Old path | New path |
| --- | --- |
| `podvm_windows::{Plan, Accel, accel_for, argv, commit_argv (now convert_argv), overlay_argv, Request, Outcome, Stop, Fat16, Ceiling, Code, outcome, stop, scratch_of}` | `pod_guest::*`, re-exported by `podvm_windows` |
| `podvm_windows::{agent, fat16, fetch, plan, qmp}` | `pod_guest::{agent, fat16, fetch, plan, qmp}`, re-exported |
| `podvm_windows::{stage, run, provision, cleanup, scratch_dir, mailbox}(...)` | `pod_guest::*(&settings, ...)`; podvm keeps its functions as calls with `podvm_windows::settings()` |
| `podvm_windows::RunGuard::arm(&plan)` | `pod_guest::RunGuard::arm(&settings, &plan)`; podvm keeps `RunGuard::arm(&plan)` |
| `podvm_windows::SCRATCH_PREFIX`, `PODVM_WINDOWS_KEEP`, `XDG_RUNTIME_DIR` | `Settings::{scratch_prefix, keep, scratch_root}`, podvm's values in `settings()` |
| the marker `podvm`, the OEM name `PODVM` | `Settings::{marker, oem}`; `podvm_windows::dos::stage` gives the marker `podvm-dos` |
| `podvm_windows::Error`, `Error::Timeout(d, stop)` | `pod_core::Failure`; `podvm_windows::timeout_of(&e)` gives `Timeout { after, stop }` |
| `podvm_windows::FetchError` | `pod_guest::fetch::Refusal`, the cause of the `Failure` (`fetch::refusal`) |
| `podvm_windows::agent::nonce() -> String` | `-> Result<String>`; podvm reads a failure as a runtime error |
| `podvm_windows::keys` (private) | `pod_guest::qmp::key` |
| `podvm_windows::{base_cache, cap_status}`, `podvm_windows::dos::base_cache` | stay in podvm |
| `podvm_windows::dos::{argv, run, batch_from_argv, DEFAULT_MEM_MIB, CPUS, ...}` | `pod_guest::dos::*`, re-exported by `podvm_windows::dos` |
| `crates/podvm-windows/src/{agent,dos,emulator,fat16,fat16/tests,fetch,plan,provision,qmp,scratch}.rs` | leave podvm |

## Tests

`cargo test -p pod-guest`. The unit tests use a temporary directory each.
The tests of the agent walk `AGENT_CMD` line by line over a mailbox of
names and texts (`src/agent/tests.rs`): the order of the marker, the
command, the result and the shutdown, the keep-alive loop over three
tokens, the 600 tries with no mailbox, and a swap of the medium (a time
with no marker, then a new medium with the next token; the marker is
written in each poll). A line that the walk does not know fails the test.
The tests with a fake emulator run `/bin/sh` and skip with a line
`skipping, REASON` where it is missing. A stop test reads a script with
`/bin/sh`, so that no test executes a file that a test thread just wrote
(`ETXTBSY`). `a_real_emulator_answers_qmp_and_leaves_no_process` starts
`qemu-system-x86_64 -M none -accel tcg` (and `-accel kvm` where `/dev/kvm` opens) with a bound on each wait, checks
the QMP handshake and a request, stops it and checks that no emulator
stays; they skip as the text above says. `guest.yml` runs them on a runner with
QEMU, each week and by hand (`docs/design.md`, section 9).
`provision::tests::a_provision_whose_keys_fail_leaves_no_emulator` runs
`provision` with a stand-in emulator and a QMP stand-in that refuses each
`send-key`, and checks that no emulator stays after the failure; the plant
`guest-t622-guard-leaves-the-emulator` proves it.

The tests of the warm start (`src/warm/tests.rs`, `src/warm/tests_start.rs`)
check the fingerprint (no path of a run, each option, one line for each
input, the CPU of the host, the version of a stand-in emulator), the
restore line, the idle agent, and the save and the load against a QMP
stand-in on a Unix socket (each file, the order of the requests, a blocked
device, a command on the mailbox, a failed migration, a relative base, a
status after the load, an emulator that exits). The fallback runs `start`
with `true` as `qemu-img`: no state, a stale state and a state with a
file missing boot cold, and so does a state whose emulator (`/bin/sh`)
exits during the load, with the store of the caller back; a stand-in
emulator with a QMP stand-in starts warm with the next command. Two tests
in `src/warm/live.rs` start the QEMU of the host with a firmware of `hlt`:
a line with no NVMe disk saves, loads, runs, and a stream cut short ends
the emulator; the plan line saves from QEMU 11 and starts warm, and an
older QEMU refuses the save with its reasons and `start` boots cold.

The tests of the next command (`src/swap/tests.rs`) check the settled
result (no swap while `WQGO.TXT` is on the medium), the refusal of an NVMe
mailbox, the new medium in the other file with another volume id and the
request of the change against a QMP stand-in, and a refusal of the
emulator that keeps the medium and the token.
`a_real_emulator_changes_the_medium_of_a_usb_mailbox` starts the QEMU of
the host with the plan line of a USB mailbox and a firmware of `hlt`,
swaps two times, and reads the new file in `query-block`; it skips where
no `qemu-system-x86_64` or `qemu-img` is on `PATH`.
`tests/windows_keep_live.rs` (ignored; `guest-windows.yml` runs it by
hand under KVM) installs Windows Server 2019 Server Core from the
evaluation ISO with the agent, runs a first command and two next commands
on new media, checks the three outcomes, and prints if a write into a
mounted USB and a mounted NVMe mailbox reached the agent.

The tests of the store (`src/fetch/tests/stand.rs`) run against the HTTP
stand-in of `pod-testkit` on the loopback, with a small HTTP/1.1 client
whose body is the rest of the connection, so that the store and not the
client checks each size: a body that breaks once and resumes by Range, a
partial file of an earlier call (pinned and not pinned), a `200` to a
Range, a body past its `Content-Length`, a `206` from another offset, a
`Content-Range` that disagrees with its `Content-Length`, an object whose
size changes between two answers, a range over the ceiling, a `416` of a
whole file, a `404` and a `503` on each try. They skip where the host has
no loopback.

The tests of the modloop build their images with the test writer of
`src/squashfs/writer.rs` (stored metadata in blocks of a chosen size, so
that an inode or a listing crosses blocks; stored, sparse and xz blocks;
fragments; an export table). Its xz blocks come from the fixtures of
`tests/fixtures/squashfs/`, which `make.py` writes with Python's lzma:
4 KiB of x86 code with the x86 BCJ filter, and 1,000 bytes with LZMA2
only. Each malformed image is a test of its fault, and 3,000 mutations of
an image read to a value or a fault. The ignored test
`write_the_fuzz_seeds` writes the seeds of the fuzz target
`squashfs_image`.

`tests/modloop_live.rs` (ignored; `live.yml` runs it each day) reads the
modloop of Alpine 3.22 that `POD_GUEST_MODLOOP` names: it walks each
directory and file, the id and export tables, counts the xz streams that
it decoded and those with the x86 filter, and takes the module set of
`nf_tables nft_nat sch_netem wireguard tun veth nf_nat`. On the
`modloop-virt` of Alpine 3.22.8 (2026-11-11): 1,016 streams, 8 with x86
BCJ, 939 files of 114,162,529 bytes; the set has 20 modules of 2,194,724
bytes for `6.12.115-0-virt`.

## Sources

`SOURCES` lists each imported file of podvm with its blob, and the
`check-sources.py` check compares them with podvm's `main`.
