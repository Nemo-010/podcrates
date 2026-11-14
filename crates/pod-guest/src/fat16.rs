//! The mailbox volume: a FAT16 image behind an MBR partition, built and
//! read in process.
//!
//! The agent of the UEFI flavour is `cmd.exe`, and `cmd.exe` gets a file
//! only through a volume that the guest mounts. `mkfs.fat` and `mtools`
//! are packages of the host; this module writes the small, fixed format
//! itself.
//!
//! The geometry is the tested one: a volume of 16 MiB behind an MBR
//! partition at LBA 2048, as measured against Validation OS. Windows does
//! not mount a volume with no partition table as a fixed NVMe disk every
//! time. The cluster is 4 KiB, so that the count of clusters stays below
//! 65525, the limit of FAT16.
//!
//! Each file of the protocol (`WQMARK.TXT`, `WQGO.TXT`, `WQCMD.CMD`,
//! `WQOUT.TXT`, `WQERR.TXT`, `WQCODE.TXT`, `WQAGENT.CMD`, `WA.CMD`,
//! `SETUP.TXT`) is 8.3, and [`Fat16::put`] writes such a name as one entry.
//! A longer name (`autounattend.xml`, which Windows Setup reads from the
//! root of a USB medium) gets VFAT long-name entries and an 8.3 alias.
//! [`Fat16::put`] refuses each other name and names it: a changed name is
//! a file that the guest does not find.

use pod_core::Class;

use crate::{Result, failure};

/// The sector: the unit of the volume and of the kernel.
pub const SECTOR: usize = 512;
/// 4 KiB clusters.
pub const SECTORS_PER_CLUSTER: usize = 8;
/// The reserved sectors of the volume, as the BPB records them.
pub const RESERVED_SECTORS: usize = 1;
/// Two FATs: a reader that trusts the second copy expects it.
pub const NUM_FATS: usize = 2;
/// 512 root entries, so 32 sectors: the fixed root of FAT16.
pub const ROOT_ENTRIES: usize = 512;
/// The volume itself, 16 MiB.
pub const VOLUME_SECTORS: usize = 32768;
/// Sectors for each FAT. A fixed value, not a computed one: the checks at
/// compile time below compare it with the count of clusters, so a wrong
/// value does not build.
pub const FAT_SECTORS: usize = 16;
/// The first sector of the partition.
pub const PART_LBA: usize = 2048;
/// The MBR partition type for a FAT16 volume of this size.
pub const PART_TYPE: u8 = 0x06;
/// `ROOT_ENTRIES * 32 / SECTOR`.
pub const ROOT_SECTORS: usize = ROOT_ENTRIES * 32 / SECTOR;
/// The first data sector, in sectors from the start of the volume.
pub const DATA_SECTOR: usize = RESERVED_SECTORS + NUM_FATS * FAT_SECTORS + ROOT_SECTORS;
/// The count of clusters of the geometry.
pub const CLUSTERS: usize = (VOLUME_SECTORS - DATA_SECTOR) / SECTORS_PER_CLUSTER;
/// The whole image, MBR included.
pub const IMAGE_SECTORS: usize = PART_LBA + VOLUME_SECTORS;
/// The whole image in bytes.
pub const IMAGE_LEN: usize = IMAGE_SECTORS * SECTOR;
/// The label of the volume in the BPB. [`Fat16::is_mailbox`] reads it.
pub const LABEL: &str = "WQMAILBOX";
/// The volume id of a new volume ([`Fat16::volume_id`]).
pub const VOLUME_ID: u32 = 0x504F_4442;

/// A check at compile time: the FAT holds each cluster of the geometry.
/// `(CLUSTERS + 2) * 2` is the size of the FAT in bytes.
const _: () = assert!(CLUSTERS + 2 <= FAT_SECTORS * SECTOR / 2);
const _: () = assert!(CLUSTERS + 2 < 0xFFF0, "FAT16, not FAT32");
// The volume is not a multiple of the cluster: the data area keeps the
// whole clusters that fit, and no file uses the rest.
const _: () = assert!(DATA_SECTOR + CLUSTERS * SECTORS_PER_CLUSTER <= VOLUME_SECTORS);
const _: () = assert!(VOLUME_SECTORS - (DATA_SECTOR + CLUSTERS * SECTORS_PER_CLUSTER) < SECTORS_PER_CLUSTER);

/// One volume in memory: the whole image, with the MBR.
#[derive(Clone)]
pub struct Fat16 {
    image: Vec<u8>,
}

impl Default for Fat16 {
    fn default() -> Self {
        Self::new()
    }
}

impl Fat16 {
    /// A formatted, empty volume with the OEM name [`OEM`].
    pub fn new() -> Self {
        Fat16 { image: format() }
    }

    /// A formatted, empty volume with the OEM name `oem`: at most 8
    /// printable ASCII characters.
    pub fn with_oem(oem: &str) -> Result<Self> {
        Ok(Fat16 { image: format_with(oem_bytes(oem)?) })
    }

    /// Take an image that a run wrote, so that the host reads the results
    /// with no new volume. `None`: the image is too short.
    pub fn from_image(image: Vec<u8>) -> Option<Self> {
        if image.len() < IMAGE_LEN {
            return None;
        }
        Some(Fat16 { image })
    }

    pub fn image(&self) -> &[u8] {
        &self.image
    }

    pub fn into_image(self) -> Vec<u8> {
        self.image
    }

    /// Write `data` as `name`, in place of a file of that name. An 8.3 name
    /// becomes upper case, with the case byte of Windows. A long name of up
    /// to [`MAX_LONG_NAME`] characters gets VFAT long-name entries before an
    /// 8.3 alias (`AUTOUN~1.XML`) that no other file has; a file of that
    /// long name keeps its alias. Each other name is a [`Class::Usage`]
    /// failure that names it. A full volume or root is
    /// [`Class::Unavailable`].
    pub fn put(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let parsed = names::parse(name)?;
        if let Some(f) = self.find(name, &parsed) {
            self.free_chain(f.first);
            let case = if let names::Name::Short(_, case) = parsed { case } else { f.entry[12] };
            let wrote = self.write_entry(f.slot, &f.short(), case, data);
            if wrote.is_err() {
                // The old clusters are free: no entry keeps them.
                self.drop_entries(f.slot);
            }
            return wrote;
        }
        match parsed {
            names::Name::Short(bare, case) => {
                let slot = self.free_run(1)?;
                self.write_entry(slot, &bare, case, data)
            }
            names::Name::Long(long) => {
                let files = self.walk();
                let short = names::alias(&long, |a| files.iter().any(|f| &f.short() == a))?;
                let longs = names::long_entries(&long, &short);
                let at = self.free_run(longs.len() + 1)?;
                // The 8.3 entry first: a volume that is full leaves no long
                // name with no file.
                self.write_entry(at + longs.len(), &short, 0, data)?;
                for (k, e) in longs.iter().enumerate() {
                    self.put_entry(at + k, e);
                }
                Ok(())
            }
        }
    }

    /// Remove `name`, as [`Fat16::put`] reads it, and free its clusters.
    /// `Ok(false)`: no such file. The long-name entries before it go too,
    /// also a chain that does not read as a name, so that no orphan stays.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let parsed = names::parse(name)?;
        let Some(f) = self.find(name, &parsed) else { return Ok(false) };
        self.free_chain(f.first);
        self.drop_entries(f.slot);
        Ok(true)
    }

    /// Mark the entry `slot` and the long-name entries just before it free.
    fn drop_entries(&mut self, slot: usize) {
        let mut i = slot;
        loop {
            let mut e = self.entry(i);
            e[0] = 0xE5;
            self.put_entry(i, &e);
            match i.checked_sub(1) {
                Some(j) if self.entry(j)[11] == names::LONG_ATTR && self.entry(j)[0] != 0xE5 => i = j,
                _ => return,
            }
        }
    }

    /// The bytes of `name` (an 8.3 name or a long name, in any case), or
    /// `None` where it is not in the root.
    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        let f = self.find(name, &names::parse(name).ok()?)?;
        self.read_chain(f.first, f.size)
    }

    /// Each file name in the root, in the order of the directory: the long
    /// name where the volume has one, else the 8.3 name.
    pub fn list(&self) -> Vec<String> {
        self.walk().into_iter().map(|f| f.long.unwrap_or_else(|| names::render_short(&f.entry))).collect()
    }

    /// True when the volume has the label [`LABEL`]: a reader that is sure
    /// to look at a mailbox.
    pub fn is_mailbox(&self) -> bool {
        let base = PART_LBA * SECTOR;
        self.image[base + 0x2B..base + 0x36] == label_bytes()
    }

    /// The volume id of the boot sector. Windows reads a medium again only
    /// when its volume id differs ([`crate::swap`]).
    pub fn volume_id(&self) -> u32 {
        let at = PART_LBA * SECTOR + 39;
        u32::from_le_bytes([self.image[at], self.image[at + 1], self.image[at + 2], self.image[at + 3]])
    }

    pub fn set_volume_id(&mut self, id: u32) {
        let at = PART_LBA * SECTOR + 39;
        self.image[at..at + 4].copy_from_slice(&id.to_le_bytes());
    }

    // ---------------------------------------------------------------- layout

    fn fat(&self, n: u16) -> u16 {
        let base = PART_LBA * SECTOR + RESERVED_SECTORS * SECTOR;
        let at = base + usize::from(n) * 2;
        u16::from_le_bytes([self.image[at], self.image[at + 1]])
    }

    fn set_fat(&mut self, n: u16, v: u16) {
        let base = PART_LBA * SECTOR + RESERVED_SECTORS * SECTOR;
        for fat in 0..NUM_FATS {
            let at = base + fat * FAT_SECTORS * SECTOR + usize::from(n) * 2;
            self.image[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
    }

    fn cluster_at(&self, n: u16) -> usize {
        let sector = DATA_SECTOR + (usize::from(n) - 2) * SECTORS_PER_CLUSTER;
        (PART_LBA + sector) * SECTOR
    }

    fn entry(&self, i: usize) -> [u8; 32] {
        let at = PART_LBA * SECTOR + DATA_SECTOR * SECTOR - ROOT_SECTORS * SECTOR + i * 32;
        let mut e = [0u8; 32];
        e.copy_from_slice(&self.image[at..at + 32]);
        e
    }

    fn put_entry(&mut self, i: usize, e: &[u8; 32]) {
        let at = PART_LBA * SECTOR + DATA_SECTOR * SECTOR - ROOT_SECTORS * SECTOR + i * 32;
        self.image[at..at + 32].copy_from_slice(e);
    }

    /// Each file of the root, with the long name of the whole chain of
    /// long-name entries before it.
    fn walk(&self) -> Vec<Found> {
        let mut out = Vec::new();
        let mut longs: Vec<[u8; 32]> = Vec::new();
        for slot in 0..ROOT_ENTRIES {
            let entry = self.entry(slot);
            if entry[0] == 0x00 {
                break;
            }
            if entry[0] == 0xE5 {
                longs.clear();
            } else if entry[11] == names::LONG_ATTR {
                longs.push(entry);
            } else if entry[11] & 0x18 != 0 {
                longs.clear();
            } else {
                let mut short = [0u8; 11];
                short.copy_from_slice(&entry[0..11]);
                let long = names::read_long(&longs, &short);
                longs.clear();
                let first = u16::from_le_bytes([entry[26], entry[27]]);
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                out.push(Found { slot, entry, long, first, size });
            }
        }
        out
    }

    /// The file of `name`: by its 8.3 name, or by its long name in any case.
    fn find(&self, name: &str, parsed: &names::Name) -> Option<Found> {
        let upper = name.to_uppercase();
        self.walk().into_iter().find(|f| {
            let long = f.long.as_ref().is_some_and(|l| l.to_uppercase() == upper);
            long || matches!(parsed, names::Name::Short(bare, _) if f.short() == *bare)
        })
    }

    /// The first of `n` free slots in a row of the root.
    fn free_run(&self, n: usize) -> Result<usize> {
        let free = |i: usize| matches!(self.entry(i)[0], 0x00 | 0xE5);
        (0..=ROOT_ENTRIES.saturating_sub(n))
            .find(|at| (*at..at + n).all(free))
            .ok_or_else(|| failure(Class::Unavailable, "the mailbox root is full"))
    }

    /// The first cluster with a free FAT entry, marking it used.
    fn take_cluster(&mut self) -> Result<u16> {
        for n in 2..(CLUSTERS as u16 + 2) {
            if self.fat(n) == 0 {
                self.set_fat(n, 0xFFFF);
                return Ok(n);
            }
        }
        Err(failure(Class::Unavailable, "the mailbox volume is full"))
    }

    fn write_entry(&mut self, slot: usize, bare: &[u8; 11], case: u8, data: &[u8]) -> Result<()> {
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(bare);
        e[11] = 0x20; // archive
        e[12] = case;
        // The FAT time is 1980-01-01: a fixed value, not the clock of the
        // host, so that the image is the same byte for byte.
        e[14] = 0x00;
        e[15] = 0x00;
        e[16] = 0x21;
        e[22] = 0x00;
        e[23] = 0x00;
        e[24] = 0x21;
        // A size of more than 4 GiB does not fit in the entry; the volume
        // is 16 MiB, so it is full first. No truncation on a 64-bit host.
        let size = u32::try_from(data.len()).map_err(|_| failure(Class::Unavailable, "the mailbox volume is full"))?;
        if size == 0 {
            e[26] = 0;
            e[27] = 0;
            self.put_entry(slot, &e);
            return Ok(());
        }
        let first = self.take_cluster()?;
        if let Err(full) = self.write_chain(first, data) {
            // The clusters of a file that did not fit go back.
            self.free_chain(first);
            return Err(full);
        }
        e[26] = (first & 0xFF) as u8;
        e[27] = (first >> 8) as u8;
        e[28..32].copy_from_slice(&size.to_le_bytes());
        self.put_entry(slot, &e);
        Ok(())
    }

    /// Write `data` into a chain from the cluster `first`, which is taken.
    fn write_chain(&mut self, first: u16, data: &[u8]) -> Result<()> {
        let mut n = first;
        let mut off = 0usize;
        loop {
            let at = self.cluster_at(n);
            let take = core::cmp::min(SECTORS_PER_CLUSTER * SECTOR, data.len() - off);
            self.image[at..at + take].copy_from_slice(&data[off..off + take]);
            off += take;
            if off >= data.len() {
                self.set_fat(n, 0xFFFF);
                return Ok(());
            }
            let next = self.take_cluster()?;
            self.set_fat(n, next);
            n = next;
        }
    }

    /// The bytes of a chain. The guest wrote the volume, so the chain is
    /// not trusted: a cluster outside the volume, a loop, or a size that
    /// the chain does not hold reads as `None`, never as a panic or as an
    /// allocation of the size in the entry.
    fn read_chain(&self, first: u16, size: u32) -> Option<Vec<u8>> {
        let size = usize::try_from(size).ok()?;
        if size > CLUSTERS * SECTORS_PER_CLUSTER * SECTOR {
            return None;
        }
        let mut out = Vec::with_capacity(size);
        let mut seen = vec![false; CLUSTERS + 2];
        let mut n = first;
        while in_volume(n) && out.len() < size {
            if std::mem::replace(&mut seen[usize::from(n)], true) {
                return None;
            }
            let at = self.cluster_at(n);
            let take = core::cmp::min(SECTORS_PER_CLUSTER * SECTOR, size - out.len());
            out.extend_from_slice(&self.image[at..at + take]);
            n = self.fat(n);
        }
        if out.len() != size {
            return None;
        }
        Some(out)
    }

    fn free_chain(&mut self, mut n: u16) {
        // A freed entry becomes 0, so a loop in the chain ends at the
        // first cluster that it meets again.
        while in_volume(n) {
            let next = self.fat(n);
            self.set_fat(n, 0);
            n = next;
        }
    }
}

/// One file of the root: its slot, its 8.3 entry, and its long name.
struct Found {
    slot: usize,
    entry: [u8; 32],
    long: Option<String>,
    first: u16,
    size: u32,
}

impl Found {
    fn short(&self) -> [u8; 11] {
        let mut out = [0u8; 11];
        out.copy_from_slice(&self.entry[0..11]);
        out
    }
}

/// True when `n` is a data cluster of the volume.
fn in_volume(n: u16) -> bool {
    (2..CLUSTERS as u16 + 2).contains(&n)
}

/// The OEM name of [`Fat16::new`] and [`format()`].
pub const OEM: &str = "PODGUEST";

/// The 8 bytes of an OEM name, padded with spaces. More than 8 bytes, or a
/// byte that is not printable ASCII, is a [`Class::Usage`] failure.
pub fn oem_bytes(oem: &str) -> Result<[u8; 8]> {
    if oem.len() > 8 || !oem.bytes().all(|c| c.is_ascii_graphic() || c == b' ') {
        return Err(failure(Class::Usage, format!("{oem:?} is not an OEM name: 8 printable ASCII characters at most")));
    }
    let mut out = [b' '; 8];
    out[..oem.len()].copy_from_slice(oem.as_bytes());
    Ok(out)
}

/// A formatted, empty mailbox image with the OEM name [`OEM`].
pub fn format() -> Vec<u8> {
    let mut oem = [b' '; 8];
    oem.copy_from_slice(OEM.as_bytes());
    format_with(oem)
}

/// A formatted, empty mailbox image with the OEM name `oem`.
pub fn format_with(oem: [u8; 8]) -> Vec<u8> {
    let mut img = vec![0u8; IMAGE_LEN];
    // ------------------------------------------------------------------ MBR
    img[0x1BE] = 0x00; // not bootable
    img[0x1BF] = 0x00; // start CHS, head
    img[0x1C0] = 0x02; // start CHS, sector 1 (1-based) of cylinder 0
    img[0x1C1] = 0x00; // start CHS, cylinder
    img[0x1C2] = PART_TYPE;
    img[0x1C3] = 0xFE; // end CHS, head
    img[0x1C4] = 0xFF; // end CHS, sector
    img[0x1C5] = 0xFF; // end CHS, cylinder
    img[0x1C6..0x1CA].copy_from_slice(&(PART_LBA as u32).to_le_bytes());
    img[0x1CA..0x1CE].copy_from_slice(&(VOLUME_SECTORS as u32).to_le_bytes());
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    // ------------------------------------------------------------------ BPB
    let b = PART_LBA * SECTOR;
    img[b..b + 3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[b + 3..b + 11].copy_from_slice(&oem);
    img[b + 11..b + 13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    img[b + 13] = SECTORS_PER_CLUSTER as u8;
    img[b + 14..b + 16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    img[b + 16] = NUM_FATS as u8;
    img[b + 17..b + 19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    img[b + 19..b + 21].copy_from_slice(&(VOLUME_SECTORS as u16).to_le_bytes());
    img[b + 21] = 0xF8; // fixed disk
    img[b + 22..b + 24].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
    img[b + 24..b + 26].copy_from_slice(&32u16.to_le_bytes()); // sectors/track
    img[b + 26..b + 28].copy_from_slice(&64u16.to_le_bytes()); // heads
    img[b + 28..b + 32].copy_from_slice(&(PART_LBA as u32).to_le_bytes()); // hidden
    img[b + 32..b + 36].copy_from_slice(&(VOLUME_SECTORS as u32).to_le_bytes());
    img[b + 36] = 0x80; // drive number
    img[b + 38] = 0x29; // extended boot signature
    img[b + 39..b + 43].copy_from_slice(&VOLUME_ID.to_le_bytes());
    img[b + 43..b + 54].copy_from_slice(&label_bytes());
    img[b + 54..b + 62].copy_from_slice(b"FAT16   ");
    img[b + SECTOR - 2] = 0x55;
    img[b + SECTOR - 1] = 0xAA;

    // ------------------------------------------------------------------ FAT
    let fat = b + RESERVED_SECTORS * SECTOR;
    for f in 0..NUM_FATS {
        let at = fat + f * FAT_SECTORS * SECTOR;
        img[at..at + 2].copy_from_slice(&0xFFF8u16.to_le_bytes());
        img[at + 2..at + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
    }
    img
}

fn label_bytes() -> [u8; 11] {
    let mut out = [b' '; 11];
    let l = LABEL.as_bytes();
    out[..l.len()].copy_from_slice(l);
    out
}

mod names;

pub use names::{MAX_LONG_NAME, checksum};

#[cfg(test)]
mod tests;
