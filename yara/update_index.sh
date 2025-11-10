#!/usr/bin/env bash

find . -name "*.yara" -not -name "index.yara"  |  sed -e 's/^/include "/g' | sed -e 's/$/"/g' >index.yara
