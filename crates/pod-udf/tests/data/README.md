# Images of real mastering tools

`tests/tools.rs` reads these images. Each image is kept with `gzip -9n`:
the tools pad an image with zeros.

## The tree

```sh
mkdir -p tree/sources/deep/deeper tree/efi
printf 'MZ setup' > tree/setup.exe
printf 'hello' > tree/sources/boot.wim
python3 -c "import sys;sys.stdout.buffer.write(bytes(i%251 for i in range(3*2048+100)))" > tree/sources/install.wim
printf 'leaf' > tree/sources/deep/deeper/leaf.txt
: > tree/sources/empty.txt
```

## `genisoimage-udf102.iso.gz`

genisoimage 1.1.11 (Ubuntu 24.04, package `genisoimage`): an ISO 9660 and
UDF 1.02 bridge, the form of the ISO images of Windows.

```sh
genisoimage -quiet -udf -V PODUDF -o genisoimage-udf102.iso tree
gzip -9n genisoimage-udf102.iso
```

xorriso 1.5.6 refuses `-as mkisofs -udf` ("Unsupported option"): it
writes no UDF.

## `mkudffs-udf201.img.gz`

mkudffs of udftools 2.3 (package `udftools`): an empty UDF 2.01 volume.
A file goes into such a volume only through a mount, and the kernel of a
cloud session has no UDF.

```sh
truncate -s 600K mkudffs-udf201.img
mkudffs --media-type=hd --udfrev=2.01 --blocksize=2048 --label=PODUDF \
    --uuid=0000000000000001 mkudffs-udf201.img
gzip -9n mkudffs-udf201.img
```

## `mkudffs-bdr-udf250.img.gz`

mkudffs 2.3 writes UDF 2.50 and 2.60 only for write-once media (`bdr`,
`dvdr`), with a virtual allocation table. The reader refuses that
partition map by name.

```sh
truncate -s 1M mkudffs-bdr-udf250.img
mkudffs --media-type=bdr --udfrev=2.50 --blocksize=2048 --label=PODUDF \
    --uuid=0000000000000001 mkudffs-bdr-udf250.img
gzip -9n mkudffs-bdr-udf250.img
```
