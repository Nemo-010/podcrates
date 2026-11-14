use super::*;

#[test]
fn a_formatted_volume_declares_its_geometry_and_its_label() {
    let img = format();
    assert_eq!(img.len(), IMAGE_LEN);
    assert_eq!(u16::from_le_bytes([img[0x1FE], img[0x1FF]]), 0xAA55);
    assert_eq!(img[0x1C2], PART_TYPE);
    assert_eq!(u32::from_le_bytes([img[0x1C6], img[0x1C7], img[0x1C8], img[0x1C9]]), PART_LBA as u32);
    let b = PART_LBA * SECTOR;
    assert_eq!(&img[b + 54..b + 62], b"FAT16   ");
    assert_eq!(img[b + 13], SECTORS_PER_CLUSTER as u8);
    assert_eq!(img[b + 16], NUM_FATS as u8);
    assert!(Fat16::from_image(img).unwrap().is_mailbox());
}

#[test]
fn the_built_volume_declares_the_geometry_it_was_pinned_to() {
    // The checks at compile time fix the arithmetic; this test checks the
    // bytes that a guest mounts.
    let m = Fat16::new();
    let img = m.image();
    let base = PART_LBA * SECTOR;
    let bpb = |o: usize| u16::from_le_bytes([img[base + o], img[base + o + 1]]);
    assert_eq!(bpb(11), SECTOR as u16, "bytes per sector");
    assert_eq!(img[base + 13] as usize, SECTORS_PER_CLUSTER, "sectors per cluster");
    assert_eq!(bpb(14) as usize, RESERVED_SECTORS, "reserved sectors");
    assert_eq!(img[base + 16] as usize, NUM_FATS, "two FATs");
    assert_eq!(bpb(17) as usize, ROOT_ENTRIES, "root entries");
    assert_eq!(bpb(22) as usize, FAT_SECTORS, "sectors per FAT");
    let mut padded = [b' '; 11];
    padded[..LABEL.len()].copy_from_slice(LABEL.as_bytes());
    assert_eq!(&img[base + 43..base + 54], &padded, "volume label");
    assert_eq!([img[510], img[511]], [0x55, 0xAA], "MBR signature");
    assert_eq!(img[446 + 4], PART_TYPE, "partition type");
}

#[test]
fn a_file_round_trips_through_the_volume() {
    let mut v = Fat16::new();
    v.put("WQMARK.TXT", b"guest").unwrap();
    assert_eq!(v.get("WQMARK.TXT").as_deref(), Some(&b"guest"[..]));
    assert!(v.is_mailbox());
}

#[test]
fn a_file_that_spans_clusters_comes_back_whole() {
    let mut v = Fat16::new();
    let big: Vec<u8> = (0..(SECTORS_PER_CLUSTER * SECTOR * 3 + 7)).map(|i| (i % 251) as u8).collect();
    v.put("BIG.BIN", &big).unwrap();
    assert_eq!(v.get("BIG.BIN").as_deref(), Some(&big[..]));
}

#[test]
fn an_empty_file_has_no_cluster_and_reads_back_empty() {
    let mut v = Fat16::new();
    v.put("EMPTY.TXT", b"").unwrap();
    assert_eq!(v.get("EMPTY.TXT").as_deref(), Some(&b""[..]));
}

#[test]
fn rewriting_a_name_replaces_the_bytes_and_frees_the_old_chain() {
    let mut v = Fat16::new();
    v.put("WQOUT.TXT", &vec![b'a'; 20_000]).unwrap();
    // Five clusters, so cluster 2 starts a chain and does not end it.
    assert_eq!(v.fat(2), 3);
    assert_ne!(v.fat(3), 0);
    v.put("WQOUT.TXT", b"short").unwrap();
    assert_eq!(v.get("WQOUT.TXT").as_deref(), Some(&b"short"[..]));
    // The clusters of the long file after the first are free, and
    // cluster 2 holds the whole file, so its entry ends a chain.
    assert_eq!(v.fat(2), 0xFFFF);
    assert_eq!(v.fat(3), 0);
}

#[test]
fn the_root_lists_what_was_written() {
    let mut v = Fat16::new();
    v.put("WQMARK.TXT", b"x").unwrap();
    v.put("WQGO.TXT", b"token").unwrap();
    let mut l = v.list();
    l.sort();
    assert_eq!(l, vec!["WQGO.TXT", "WQMARK.TXT"]);
}

#[test]
fn names_are_8_3_or_they_are_refused_naming_themselves() {
    let mut v = Fat16::new();
    assert!(v.put("WQCODE.TXT", b"0 t").is_ok());
    assert!(v.put("ADIR", b"x").is_ok());
    // A name that is neither 8.3 nor a long name that FAT keeps is
    // refused: empty, too long, a character that FAT refuses, a dot or a
    // space at the end, a character out of UCS-2.
    let long33 = "a".repeat(MAX_LONG_NAME + 1);
    for bad in ["", long33.as_str(), "a/b.txt", "c:d", "q?.xml", "x.y.", "end ", "..", "tab\t.txt", "\u{1F600}.txt"] {
        let e = v.put(bad, b"x").err().unwrap_or_else(|| panic!("{bad:?} was taken"));
        assert_eq!(e.class, pod_core::Class::Usage, "{bad:?}");
    }
    let e = v.put("what?.txt", b"x").unwrap_err();
    assert!(e.to_string().contains("what?.txt"), "{e}");
    // A name longer than 8.3 is a long name now.
    assert!(v.put("toolongname.txt", b"x").is_ok());
    assert_eq!(v.get("TOOLONGNAME.TXT").as_deref(), Some(&b"x"[..]));
}

#[test]
fn a_lowercase_name_round_trips_as_written() {
    let mut v = Fat16::new();
    v.put("wqcmd.cmd", b"x").unwrap();
    assert!(v.list()[0].contains("wqcmd"), "{:?}", v.list());
    assert!(v.get("wqcmd.cmd").is_some());
    // It is the same file as the upper-case name: FAT ignores the case,
    // and so does the reader.
    assert!(v.get("WQCMD.CMD").is_some());
}

#[test]
fn a_missing_name_reads_as_none_and_a_built_image_adopts() {
    assert!(Fat16::from_image(vec![0u8; IMAGE_LEN]).is_some());
    let mut v = Fat16::new();
    v.put("WQMARK.TXT", b"x").unwrap();
    assert!(v.get("NOTHERE.TXT").is_none());
}

/// The OEM name is a setting of the caller, and a name that does not fit is
/// refused.
#[test]
fn the_oem_name_is_the_callers_and_a_long_one_is_refused() {
    let v = Fat16::with_oem("PODVM").unwrap();
    let b = PART_LBA * SECTOR;
    assert_eq!(&v.image()[b + 3..b + 11], b"PODVM   ");
    assert!(v.is_mailbox());
    assert_eq!(&Fat16::new().image()[b + 3..b + 11], OEM.as_bytes());
    let e = Fat16::with_oem("NINE-CHRS").err().expect("a refusal");
    assert_eq!(e.class, pod_core::Class::Usage);
    assert!(Fat16::with_oem("TAB\t").is_err());
}

/// The guest writes the volume. A chain that leaves the volume, a loop, or
/// a size that the chain does not hold reads as `None`: the reader does
/// not panic, does not loop and does not allocate the size of the entry.
#[test]
fn a_chain_that_the_guest_broke_reads_as_none() {
    let mut v = Fat16::new();
    v.put("WQCODE.TXT", b"0 token").unwrap();
    let found = v.find("WQCODE.TXT", &names::parse("WQCODE.TXT").unwrap()).unwrap();
    let (slot, first) = (found.slot, found.first);
    // A size of 1 GiB on a chain of one cluster.
    let mut e = v.entry(slot);
    e[28..32].copy_from_slice(&(1u32 << 30).to_le_bytes());
    v.put_entry(slot, &e);
    assert!(v.get("WQCODE.TXT").is_none());
    // A next cluster far outside the volume.
    e[28..32].copy_from_slice(&20_000u32.to_le_bytes());
    v.put_entry(slot, &e);
    v.set_fat(first, 0xFF00);
    assert!(v.get("WQCODE.TXT").is_none());
    // A loop: the cluster points to itself.
    v.set_fat(first, first);
    assert!(v.get("WQCODE.TXT").is_none());
    // A volume that the reader took from bytes behaves the same.
    let back = Fat16::from_image(v.into_image()).unwrap();
    assert!(back.get("WQCODE.TXT").is_none());
}

/// A removed file is gone, its clusters are free, and a name that is not
/// there or not 8.3 is no removal.
#[test]
fn a_removed_file_is_gone_and_its_clusters_are_free() {
    let mut v = Fat16::new();
    // Most of the volume: a second file of this size fits only when the
    // removal freed the clusters of the first.
    let big = vec![0x5Au8; (CLUSTERS - 4) * SECTORS_PER_CLUSTER * SECTOR];
    v.put("WQOUT.TXT", &big).unwrap();
    v.put("WQCODE.TXT", b"0 tok").unwrap();
    assert!(v.put("WQERR.TXT", &big).is_err(), "the volume is full");
    assert!(v.remove("wqout.txt").unwrap());
    assert_eq!(v.get("WQOUT.TXT"), None);
    assert_eq!(v.list(), ["WQCODE.TXT"]);
    assert!(!v.remove("WQOUT.TXT").unwrap(), "no such file");
    v.put("WQERR.TXT", &big).unwrap();
    assert_eq!(v.get("WQERR.TXT").unwrap().len(), big.len());
    assert_eq!(v.get("WQCODE.TXT").as_deref(), Some(&b"0 tok"[..]), "the other file stays");
    // An empty file has no cluster.
    v.put("WQKEEP.TXT", b"").unwrap();
    assert!(v.remove("WQKEEP.TXT").unwrap());
    assert_eq!(v.remove("not/a/name.txt").unwrap_err().class, Class::Usage);
    assert!(!v.remove("not-8.3-name.text").unwrap(), "a long name that is not there");
    // A reader of the image sees the same.
    let back = Fat16::from_image(v.image().to_vec()).unwrap();
    // The new file takes the freed slot of the removed one.
    assert_eq!(back.list(), ["WQERR.TXT", "WQCODE.TXT"]);
}

/// The guest can write a long name before an entry: the removal marks it
/// too, so that no orphan name stays in the root.
#[test]
fn a_removal_takes_the_long_name_entries_before_the_file() {
    let mut v = Fat16::new();
    v.put("WQCODE.TXT", b"0 tok").unwrap();
    let file = v.entry(0);
    let mut long = [0u8; 32];
    long[0] = 0x41;
    long[11] = 0x0F;
    v.put_entry(0, &long);
    v.put_entry(1, &file);
    assert_eq!(v.list(), ["WQCODE.TXT"]);
    assert!(v.remove("WQCODE.TXT").unwrap());
    assert_eq!(v.entry(0)[0], 0xE5, "the long name goes");
    assert_eq!(v.entry(1)[0], 0xE5);
    assert!(v.list().is_empty());
}

/// The checksum of an alias in each long-name entry, against the values
/// that mtools 4.0.43 wrote for the same names (`mkfs.fat -C m.img 2048`,
/// `mcopy -i m.img f ::autounattend.xml`, then `::autounattend-2.xml` and
/// `::windows-11-answer-file-v2026.xml`): the same aliases, and these sums.
#[test]
fn the_checksum_of_an_alias_is_the_vfat_one() {
    assert_eq!(checksum(b"AUTOUN~1XML"), 0xAB);
    assert_eq!(checksum(b"AUTOUN~2XML"), 0xCB);
    assert_eq!(checksum(b"WINDOW~1XML"), 0xD7);
}

/// A long name gets long-name entries and an alias; both read back.
#[test]
fn a_long_name_reads_back_by_its_name_and_its_alias() {
    let mut v = Fat16::new();
    v.put("WQMARK.TXT", b"m").unwrap();
    v.put("autounattend.xml", b"<unattend/>").unwrap();
    assert_eq!(v.list(), ["WQMARK.TXT", "autounattend.xml"]);
    assert_eq!(v.get("autounattend.xml").as_deref(), Some(&b"<unattend/>"[..]));
    assert_eq!(v.get("AutoUnattend.XML").as_deref(), Some(&b"<unattend/>"[..]), "FAT ignores the case");
    assert_eq!(v.get("AUTOUN~1.XML").as_deref(), Some(&b"<unattend/>"[..]), "the 8.3 alias");
    // The entries in the root: two long-name entries (16 units), then the
    // alias, each with its checksum.
    let alias = *b"AUTOUN~1XML";
    let (first, second, short) = (v.entry(1), v.entry(2), v.entry(3));
    assert_eq!(&short[0..11], &alias);
    assert_eq!((first[0], second[0]), (0x42, 0x01), "the last part first, with 0x40");
    for e in [first, second] {
        assert_eq!((e[11], e[13]), (0x0F, checksum(&alias)));
    }
    assert_eq!(&second[1..3], &u16::from(b'a').to_le_bytes());
    // "autounattend.xml" has 16 units: the second part holds 3, a NUL and
    // 0xFFFF after it.
    assert_eq!(&first[1..11], &[b'x', 0, b'm', 0, b'l', 0, 0, 0, 0xFF, 0xFF]);
    // A new content keeps the alias and the long name.
    v.put("AUTOUNATTEND.XML", b"<v2/>").unwrap();
    assert_eq!(v.list(), ["WQMARK.TXT", "autounattend.xml"]);
    assert_eq!(v.get("autounattend.xml").as_deref(), Some(&b"<v2/>"[..]));
    // The removal takes the long-name entries too.
    assert!(v.remove("autounattend.xml").unwrap());
    assert_eq!(v.list(), ["WQMARK.TXT"]);
    assert!((1..4).all(|i| v.entry(i)[0] == 0xE5));
    let back = Fat16::from_image(v.image().to_vec()).unwrap();
    assert_eq!(back.list(), ["WQMARK.TXT"]);
}

/// Two long names with one alias stem get two numbers, and an 8.3 name
/// that an alias would repeat is skipped.
#[test]
fn two_long_names_of_one_stem_get_two_aliases() {
    let mut v = Fat16::new();
    v.put("AUTOUN~1.XML", b"short").unwrap();
    v.put("autounattend.xml", b"one").unwrap();
    v.put("autounattend-2.xml", b"two").unwrap();
    let shorts: Vec<String> = (0..ROOT_ENTRIES)
        .map(|i| v.entry(i))
        .take_while(|e| e[0] != 0)
        .filter(|e| e[11] != 0x0F)
        .map(|e| String::from_utf8_lossy(&e[0..11]).to_string())
        .collect();
    assert_eq!(shorts, ["AUTOUN~1XML", "AUTOUN~2XML", "AUTOUN~3XML"]);
    assert_eq!(v.get("autounattend.xml").as_deref(), Some(&b"one"[..]));
    assert_eq!(v.get("autounattend-2.xml").as_deref(), Some(&b"two"[..]));
    assert_eq!(v.get("AUTOUN~1.XML").as_deref(), Some(&b"short"[..]));
    assert_eq!(v.list(), ["AUTOUN~1.XML", "autounattend.xml", "autounattend-2.xml"]);
}

/// A name of 32 characters takes three long-name entries; a long-name
/// chain with a wrong checksum reads as the 8.3 name alone.
#[test]
fn a_name_of_32_characters_takes_three_entries() {
    let name = "windows-11-answer-file-v2026.xml";
    assert_eq!(name.chars().count(), MAX_LONG_NAME);
    let mut v = Fat16::new();
    v.put(name, b"x").unwrap();
    assert_eq!(v.list(), [name]);
    assert_eq!(v.entry(0)[0], 0x43, "three parts");
    assert_eq!(&v.entry(3)[0..11], b"WINDOW~1XML");
    let mut bad = v.entry(1);
    bad[13] ^= 1;
    v.put_entry(1, &bad);
    assert_eq!(v.list(), ["WINDOW~1.XML"], "a chain with another checksum is no name");
}

/// The volume id sits in the extended boot sector (offset 39 of the
/// volume), and a change of it changes no other byte.
#[test]
fn the_volume_id_is_read_and_set_in_the_boot_sector() {
    let mut v = Fat16::new();
    assert_eq!(v.volume_id(), VOLUME_ID);
    v.put("WQGO.TXT", b"tok").unwrap();
    let before = v.image().to_vec();
    v.set_volume_id(0x0102_0304);
    assert_eq!(v.volume_id(), 0x0102_0304);
    let at = PART_LBA * SECTOR + 39;
    assert_eq!(&v.image()[at..at + 4], &[4, 3, 2, 1]);
    let changed: Vec<usize> = (0..before.len()).filter(|&i| before[i] != v.image()[i]).collect();
    assert_eq!(changed, [at, at + 1, at + 2, at + 3]);
    assert_eq!(v.get("WQGO.TXT").as_deref(), Some(&b"tok"[..]));
}
