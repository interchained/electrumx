'''Tri-PoW header handling for the Bitcoin class serving Interchained.

Since the fork at height 913982, Ethash-tagged block headers serialize
40 extra bytes (nNonce64 + mixHash) after the standard 80-byte header.
ElectrumX must slice transactions after the full header and store
headers with the dynamic (recorded-offset) layout.
'''

import struct

from electrumx.lib.coins import Bitcoin
from electrumx.lib.hash import double_sha256

FORK = 913982    # tri-PoW fork height (daemon chainparams)


def header(version, extras=b''):
    return (struct.pack('<i', version) + b'\x11' * 32 + b'\x22' * 32
            + struct.pack('<III', 1700000000, 0x1e0eaaa9, 42) + extras)


def coinbase_tx():
    tx = struct.pack('<i', 2)                    # version
    tx += b'\x00\x01'                            # segwit marker + flag
    tx += b'\x01'                                # one input
    tx += b'\x00' * 32 + struct.pack('<I', 0xffffffff)
    tx += b'\x03abc'                             # coinbase script
    tx += struct.pack('<I', 0xffffffff)          # sequence
    tx += b'\x01'                                # one output
    tx += struct.pack('<q', 5000000000) + b'\x00'
    tx += b'\x01\x20' + b'\x00' * 32             # witness stack
    tx += struct.pack('<I', 0)                   # locktime
    return tx


def block(version, height, extras=b''):
    return header(version, extras) + b'\x01' + coinbase_tx()


def test_uses_dynamic_header_layout():
    assert Bitcoin.STATIC_BLOCK_HEADERS is False


def test_legacy_block_parses_with_80_byte_header():
    raw = block(0x20000000, FORK + 100)
    parsed = Bitcoin.block(raw, FORK + 100)
    assert len(parsed.header) == 80
    assert len(parsed.transactions) == 1


def test_ethash_block_parses_with_120_byte_header():
    extras = struct.pack('<Q', 123456789) + b'\x33' * 32
    raw = block(0x20004000, 914572, extras)
    parsed = Bitcoin.block(raw, 914572)
    assert parsed.header == raw[:120]
    assert len(parsed.transactions) == 1


def test_prefork_tag_collision_stays_80_bytes():
    # Mainnet block 900000 carries version 0x20004000, whose tag bits
    # decode as Ethash, but it predates the fork: legacy 80-byte header.
    raw = block(0x20004000, 900000)
    parsed = Bitcoin.block(raw, 900000)
    assert len(parsed.header) == 80
    assert len(parsed.transactions) == 1


def test_yespower_and_sha256_tags_stay_80_bytes_postfork():
    for version in (0x20002000, 0x20000000):
        parsed = Bitcoin.block(block(version, FORK + 50), FORK + 50)
        assert len(parsed.header) == 80
        assert len(parsed.transactions) == 1


def test_ethash_header_hash_covers_the_full_header():
    extras = struct.pack('<Q', 7) + b'\x44' * 32
    raw = block(0x20004000, 914572, extras)
    parsed = Bitcoin.block(raw, 914572)
    assert Bitcoin.header_hash(parsed.header) == \
        double_sha256(parsed.header)
    # the hash commits to the extra fields: it differs from the hash
    # of the truncated 80-byte prefix
    assert Bitcoin.header_hash(parsed.header) != \
        Bitcoin.header_hash(parsed.header[:80])
