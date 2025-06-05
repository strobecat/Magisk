#!/usr/bin/env python3
# coding=utf8

# Copyright (c) 2015, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Enumerates source files for consumption by NDK build system."""

import os
import json

with open(os.path.join('jni', 'external', 'boringssl', 'src', 'gen', 'sources.json')) as f:
  sources = json.load(f)

# TODO(crbug.com/boringssl/542): generate_build_files.py historically reported
# all the assembly files as part of libcrypto. Merge them for now, but we
# should split them out later.
crypto = sorted("boringssl/src/" + src for src in sources['bcm']['srcs']
                                                + sources['crypto']['srcs'])
crypto_asm = sorted("boringssl/src/" + src for src in sources['bcm']['asm']
                                                    + sources['crypto']['asm']
                                                    + sources['test_support']['asm'])

print(" ".join(crypto)+" "+" ".join(crypto_asm))
