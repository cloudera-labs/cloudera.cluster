#!/usr/bin/env bash

# Created with antsibull-docs 2.3.1.post0

set -e

pushd "$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
trap "{ popd; }" EXIT

# Create collection documentation into temporary directory
rm -rf temp-rst
mkdir -p temp-rst
chmod og-w temp-rst  # antsibull-docs wants that directory only readable by itself
antsibull-docs \
    --config-file antsibull-docs.cfg \
    collection \
    --use-current \
    --squash-hierarchy \
    --dest-dir temp-rst \
    cloudera.cluster

# Copy collection documentation into source directory
rsync -cprv --delete-after temp-rst/ rst/

# Build Sphinx site
sphinx-build -M html rst build -c . -W --keep-going

# Copy Cloudera CSS overrides into source directory
cp cloudera.css build/html/_static/css
