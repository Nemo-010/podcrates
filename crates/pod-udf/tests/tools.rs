//! The reader against images that real mastering tools made (T-601). The
//! images of `src/tests` come from a writer that follows the same reading
//! of the specification as the reader; a misreading in both, or a quirk of
//! a tool, passes those tests.
//!
//! `tests/data/README.md` gives the command of each image. Each image is
//! kept with gzip: the tools pad an image with zeros to hundreds of KB.

use std::io::Read;

use pod_udf::{Error, Extent, Udf};

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut out).expect("a gzip image");
    out
}

/// The bytes of `install.wim` in the tree of the images.
fn install_wim() -> Vec<u8> {
    (0..3 * 2048 + 100).map(|i| (i % 251) as u8).collect()
}

/// genisoimage 1.1.11, `-udf`: an ISO 9660 and UDF 1.02 bridge, the form of
/// the ISO images of Windows.
#[test]
fn a_genisoimage_udf_bridge_gives_each_file_and_its_bytes() {
    let image = gunzip(include_bytes!("data/genisoimage-udf102.iso.gz"));
    let mut udf = Udf::open(image.as_slice()).expect("the UDF volume of genisoimage");
    assert_eq!((udf.block_size(), udf.revision()), (2048, 0x0102));
    let names: Vec<(String, bool)> = udf.list("/").unwrap().into_iter().map(|e| (e.name, e.directory)).collect();
    for want in [("setup.exe", false), ("sources", true), ("efi", true)] {
        assert!(names.contains(&(want.0.to_string(), want.1)), "{want:?} is not in the root: {names:?}");
    }
    for (path, want) in [
        ("/setup.exe", b"MZ setup".to_vec()),
        ("/sources/boot.wim", b"hello".to_vec()),
        ("/sources/install.wim", install_wim()),
        ("/sources/deep/deeper/leaf.txt", b"leaf".to_vec()),
        ("/sources/empty.txt", Vec::new()),
    ] {
        let extents = udf.find(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(extents.size, want.len() as u64, "{path}: the size");
        let got = udf.read(&extents, 1 << 20).unwrap();
        assert_eq!(got, want, "{path}: the bytes");
        // Each part of a recorded file is in the image, at its bytes.
        let mut at = 0usize;
        for part in &extents.parts {
            if let Extent::Data { offset, len } = *part {
                let (o, l) = (offset as usize, len as usize);
                assert_eq!(&image[o..o + l], &want[at..at + l], "{path}: a part is not at its offset");
            }
            at += part.len() as usize;
        }
    }
    assert!(udf.list("/efi").unwrap().is_empty());
    assert!(matches!(udf.find("/sources/missing.wim"), Err(Error::NotFound { .. })));
    assert!(matches!(udf.find("/sources"), Err(Error::NotAFile { .. })));
}

/// mkudffs 2.3, `--udfrev=2.01`: the volume of another tool, with its
/// reserve sequence and its integrity descriptor, and a root with no entry.
/// No file can go in it here: the kernel of the host has no UDF to mount it.
#[test]
fn an_empty_mkudffs_volume_opens() {
    let image = gunzip(include_bytes!("data/mkudffs-udf201.img.gz"));
    let mut udf = Udf::open(image.as_slice()).expect("the UDF volume of mkudffs");
    assert_eq!((udf.block_size(), udf.revision()), (2048, 0x0201));
    assert!(udf.list("/").unwrap().is_empty(), "the root of an empty volume has entries");
    assert!(matches!(udf.find("/setup.exe"), Err(Error::NotFound { .. })));
}

/// mkudffs 2.3, `--media-type=bdr --udfrev=2.50`: a volume of a write-once
/// medium, with a virtual allocation table. The reader refuses its
/// partition map by name, and does not misread it.
#[test]
fn a_mkudffs_volume_with_a_virtual_partition_is_refused_by_name() {
    let image = gunzip(include_bytes!("data/mkudffs-bdr-udf250.img.gz"));
    match Udf::open(image.as_slice()) {
        Err(Error::Unsupported { what, value }) => {
            assert_eq!((what, value.as_str()), ("a partition map", "\"*UDF Virtual Partition\""));
        }
        other => panic!("a virtual partition was not refused by name: {other:?}"),
    }
}
