#!/usr/bin/env python3
'''One-time migration: build meta/headers_offsets for an Interchained
ElectrumX database that was created while headers were stored in the
static layout (STATIC_BLOCK_HEADERS = True, every header exactly
80 bytes).

The tri-PoW change switches the Bitcoin coin class (which serves
Interchained) to the dynamic header layout, where the byte offset of
every header is recorded in meta/headers_offsets.  A database opened
without that file cannot locate its stored headers.  Because every
header stored before the first Ethash block is exactly 80 bytes, the
offsets are simply h * 80 and can be synthesized without reprocessing
a single block.

Safety: the script refuses to run if the stored headers do not divide
evenly into 80-byte records (meaning the assumption above is broken),
or if a non-trivial headers_offsets file already exists.  Run it with
the server stopped:

    python3 contrib/migrate_headers_offsets.py /path/to/db_directory
'''

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from electrumx.lib.util import LogicalFile    # noqa: E402

HEADER_SIZE = 80
CHUNK_DIGITS = 2
CHUNK_SIZE = 16000000


def main():
    if len(sys.argv) != 2:
        sys.exit(f'usage: {sys.argv[0]} <db_directory>')
    db_dir = sys.argv[1]
    meta = os.path.join(db_dir, 'meta')
    if not os.path.isdir(meta):
        sys.exit(f'no meta directory under {db_dir}')

    offsets_prefix = os.path.join(meta, 'headers_offsets')
    existing = [f for f in os.listdir(meta)
                if f.startswith('headers_offsets')]
    for name in existing:
        if os.path.getsize(os.path.join(meta, name)) > 8:
            sys.exit(f'{name} already exists and is non-trivial; '
                     'refusing to overwrite recorded offsets')

    headers = LogicalFile(os.path.join(meta, 'headers'),
                          CHUNK_DIGITS, CHUNK_SIZE)
    total = len(headers.read(0, -1))
    if total % HEADER_SIZE:
        sys.exit(f'stored headers total {total} bytes, not a multiple '
                 f'of {HEADER_SIZE}; the all-80-byte assumption is '
                 'broken, aborting')
    count = total // HEADER_SIZE
    if count == 0:
        sys.exit('no stored headers; nothing to migrate '
                 '(a fresh database creates its own offsets)')

    print(f'{count:,} stored headers, heights 0..{count - 1:,}')

    blob = b''.join(struct.pack('<Q', h * HEADER_SIZE)
                    for h in range(count + 1))
    offsets = LogicalFile(offsets_prefix, CHUNK_DIGITS, CHUNK_SIZE)
    offsets.write(0, blob)

    # Verify: last header read back through the recorded offsets must
    # equal the bytes the static layout would have served.
    def offset(h):
        return struct.unpack('<Q', offsets.read(h * 8, 8))[0]

    for h in (0, 1, count // 2, count - 1):
        start, end = offset(h), offset(h + 1)
        assert end - start == HEADER_SIZE, (h, start, end)
        assert headers.read(start, end - start) == \
            headers.read(h * HEADER_SIZE, HEADER_SIZE), h
    print(f'wrote {count + 1:,} offsets to meta/headers_offsets '
          'and verified spot heights')


if __name__ == '__main__':
    main()
