#!/bin/bash
# SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
# SPDX-License-Identifier: MIT
#
# Validates debsmith output with the real Debian toolchain inside Ubuntu.
# Usage: docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
#          bash scripts/verify-container.sh

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

ARTIFACT="$(find examples/hello/dist -maxdepth 1 -name 'hello_*_all.deb' | head -1)"
DSC="$(find examples/hello/dist -maxdepth 1 -name '*.dsc' | head -1)"

if [ -z "$ARTIFACT" ] || [ -z "$DSC" ]; then
    echo "error: run debsmith build and source first" >&2
    exit 1
fi

APT_OPTS=(-o Acquire::Retries=5 -o Acquire::http::Pipeline-Depth=0)

echo "==> installing Debian tooling"
$SUDO apt-get "${APT_OPTS[@]}" update -qq
$SUDO apt-get "${APT_OPTS[@]}" install -y -qq dpkg-dev lintian build-essential debhelper

echo "==> dpkg-deb --info"
dpkg-deb --info "$ARTIFACT"

echo "==> dpkg-deb --contents"
dpkg-deb --contents "$ARTIFACT"

echo "==> installing the package with dpkg"
$SUDO dpkg -i "$ARTIFACT"

echo "==> running the installed binary"
hello

echo "==> dpkg -s hello"
dpkg -s hello

echo "==> lintian"
LINTIAN_LOG="/tmp/debsmith-lintian.log"
lintian "$ARTIFACT" >"$LINTIAN_LOG" 2>&1 || true
cat "$LINTIAN_LOG"

if grep -qE '^E:' "$LINTIAN_LOG"; then
    echo "error: lintian reported errors" >&2
    exit 1
fi

echo "==> extracting the source package"
rm -rf /tmp/src
mkdir -p /tmp/src
dpkg-source -x "$DSC" /tmp/src/hello

echo "==> rebuilding from debian/rules"
(
    cd /tmp/src/hello
    dpkg-buildpackage -b -us -uc
)

echo "==> source package produced:"
ls -l /tmp/src/*.deb
dpkg-deb --info /tmp/src/hello_1.0.0-1_*.deb | head -20

echo "==> installing from the generated APT repository"
$SUDO apt-get purge -y -qq hello
WORKDIR="$(pwd)"
echo "deb [trusted=yes] file:${WORKDIR}/examples/hello/dist stable main" \
    | $SUDO tee /etc/apt/sources.list.d/debsmith.list >/dev/null
$SUDO apt-get "${APT_OPTS[@]}" update -qq
$SUDO apt-get "${APT_OPTS[@]}" install -y -qq --allow-downgrades hello=1.0.0-1
hello | grep -q "Hello from debsmith"
echo "installed version: $(dpkg-query -W -f='${Version}' hello)"

echo "==> ALL CONTAINER CHECKS PASSED"
