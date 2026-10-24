# hello example

A complete debsmith project with a staged payload and a Debian source tree.

```text
examples/hello/
├── debsmith.yaml          # package definition
├── rootfs/                # binary package payload
├── packaging/postinst     # maintainer script
├── src/                   # upstream sources for .orig.tar.gz
└── debian/                # control, rules, changelog, copyright, format
```

## Build and check

```bash
debsmith build . --epoch 1700000000 --sbom
debsmith lint dist/hello_1.0.0-1_all.deb --fail-on warning
debsmith inspect dist/hello_1.0.0-1_all.deb --contents --verify
debsmith verify-repro . --epoch 1700000000
```

## Source package

```bash
debsmith source . --epoch 1700000000
dpkg-source -x dist/hello_1.0.0-1.dsc /tmp/hello
cd /tmp/hello && dpkg-buildpackage -b -us -uc
```

## Repository

```bash
debsmith repo dist --epoch 1700000000
find dist/dists dist/pool -type f | sort
```

## Install

```bash
sudo dpkg -i dist/hello_1.0.0-1_all.deb
hello
```

Expected output:

```text
Hello from debsmith!
```

## Full container verification

From the repository root:

```bash
docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
  bash scripts/verify-container.sh
```
