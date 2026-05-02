#!/bin/bash

set -e
INSTALL_DIR="${HOME}/.local/bin"
BUILD_DIR="${PWD}/bin"

mkdir -p "${INSTALL_DIR}"
cp -a "${BUILD_DIR}/*" "${INSTALL_DIR}/"
