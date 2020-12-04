#!/usr/bin/env bash

# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail


# Change directories to the parent directory of the one in which this
# script is located.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

current_branch=$(git rev-parse --abbrev-ref HEAD)
docs_output_dir=docs/book/_book

if [[ ! -d $docs_output_dir ]]; then
    echo "You must build the docs first with 'make docs'"
    exit 1
fi

# Use ./_book as we switch branches to avoid conflicting with the
# gh-pages ./docs directory (one of the few options allowed by github).
rm -rf ./_book
mv $docs_output_dir ./
git checkout gh-pages

# Remove old docs site content
rm -rf ./docs/*
mv ./_book/* ./docs/
rmdir ./_book

# Commit new docs content
git add .
git commit -m "Publishing docs..."
git push origin gh-pages
echo "✅ Successfully published docs"

git checkout $current_branch
