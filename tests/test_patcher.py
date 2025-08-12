import pytest
import zlib
from pypatchergba.patcher import apply_ips, apply_ups, apply_bps, apply_patch, read_vli
import io

# --- VLI Tests ---

def test_read_vli_single_byte():
    # 0 should be encoded as 0x80
    stream = io.BytesIO(b"\x80")
    assert read_vli(stream) == 0

def test_read_vli_multi_byte():
    # 300 should be encoded as 0x2C 0x81
    stream = io.BytesIO(b"\x2C\x81")
    assert read_vli(stream) == 300

def test_read_vli_eof():
    # 0x2C has MSB of 0, meaning we will read next byte
    # however no byte exists so we should expect eof error
    stream = io.BytesIO(b"\x2C")
    with pytest.raises(EOFError):
        read_vli(stream)

# --- IPS Tests ---

def test_ips_simple_patch():
    source = b"HELLO WORLD"
    target = b"HELLO THERE" # general kenobi 
    # Patch: offset 6 (00 00 06), size 5 (00 05), payload THERE
    patch_data = b"PATCH" + b"\x00\x00\x06\x00\x05" + b"THERE" + b"EOF"
    assert apply_ips(source, patch_data) == target

def test_ips_rle_patch():
    source = b"AAAAAAAAAA" # 10 As
    target = b"ZZZZZAAAAA" # 5 Zs, 5 As
    # Patch: offset 0 (00 00 00), size 0 (00 00), RLE size 5 (00 05), byte Z
    patch_data = b"PATCH" + b"\x00\x00\x00\x00\x00" + b"\x00\x05Z" + b"EOF"
    assert apply_ips(source, patch_data) == target

def test_ips_invalid_header():
    # If IPS patch doesnt have PATCH as header we expect error
    with pytest.raises(ValueError, match="Invalid IPS patch header"):
        apply_ips(b"", b"INVALID")

def test_ips_truncated():
    # Same example as simple_patch
    patch_data = b"PATCH" + b"\x00\x00\x06\x00\x05" + b"THER" + b"EOF" # Missing 5th character E
    with pytest.raises(ValueError):
        apply_ips(b"HELLO WORLD", patch_data)

def test_ips_missing_eof():
    # Same example as simple_patch
    patch_data = b"PATCH" + b"\x00\x00\x06\x00\x05" + b"THERE" # Missing eof
    with pytest.raises(ValueError):
        apply_ips(b"HELLO WORLD", patch_data)

# --- UPS Tests ---

def test_ups_simple_patch():
    source = b"HELLO WORLD" # 11 bytes
    target = b"HELLO THERE" # 11 bytes
    # We change "WORLD" -> "THERE" - we need the XOR difference
    # W(87)^T(84)=3, O(79)^H(72)=7, R(82)^E(69)=15, L(76)^R(82)=6, D(68)^E(69)=1
    xor_payload = bytes([3, 7, 15, 6, 1])

    # Make valid UPS patch

    # Header
    patch = b"UPS1"
    # Source/Target size VLIs (11 -> 0x8B)
    patch += b"\x8B\x8B"
    # Patch body: skip 6 bytes (x86 in vli), XOR 5 bytes, then end with 0x00
    patch_body = b"\x86" + xor_payload + b"\x00"
    patch += patch_body
    # Add Footer CRCs
    patch += zlib.crc32(source).to_bytes(4, "little")
    patch += zlib.crc32(target).to_bytes(4, "little")
    patch += zlib.crc32(patch_body).to_bytes(4, "little")

    assert apply_ups(source, patch) == target

def test_ups_source_size_mismatch():
    source = b"WRONG SIZE" # 10 bytes
    # This patch expects a source file of 11 bytes (VLI 0x8B)
    # The size check happens before the CRC checks so we can expect error before then
    patch = b"UPS1" + b"\x8B\x8B" + b"\x00" + (b"\x00" * 12)
    with pytest.raises(ValueError, match="Source file size mismatch"):
        apply_ups(source, patch)

def test_ups_source_crc_mismatch():
    source = b"HELLO EVERY" # Correct length (11) but wrong content
    target = b"HELLO THERE"
    
    # This patch is valid for the correct source HELLO WORLD
    # When applied to our invalid source, the CRC must fail
    xor_payload = bytes([3, 7, 15, 6, 1])
    patch_body = b"\x86" + xor_payload + b"\x00"
    patch = b"UPS1" + b"\x8B\x8B" + patch_body
    # Use CRC of the *correct* source to build the patch
    patch += zlib.crc32(b"HELLO WORLD").to_bytes(4, "little")
    patch += zlib.crc32(target).to_bytes(4, "little")
    patch += zlib.crc32(patch_body).to_bytes(4, "little")
    
    with pytest.raises(ValueError, match="Source file is invalid"):
        apply_ups(source, patch)


# --- BPS Tests ---

def test_bps_simple_patch():
    source = b"HELLO WORLD" # 11 bytes
    target = b"HELLO THERE" # 11 bytes
    
    # Hand-craft a valid BPS patch
    patch = b"BPS1"
    # Source/Target size VLIs (11 -> 0x8B)
    # Metadata size 0 -> 0x80
    patch += b"\x8B\x8B\x80"
    
    # Patch Body:
    # Action 1: SourceRead (action 0) of length 6 to copy "HELLO "
    #   ((6 - 1) << 2) | 0 = 20 (0x14)
    # Action 2: TargetRead (action 1) of length 5 to write "THERE"
    #   ((5 - 1) << 2) | 1 = 17 (0x11)
    # The payload for TargetRead ("THERE") follows the command
    patch_body = b"\x14" + b"\x11" + b"THERE"
    patch += patch_body
    
    # Footer CRCs
    patch += zlib.crc32(source).to_bytes(4, "little")
    patch += zlib.crc32(target).to_bytes(4, "little")
    patch += zlib.crc32(patch_body).to_bytes(4, "little")

    assert apply_bps(source, patch) == target

def test_bps_source_size_mismatch():
    source = b"SHORT" # 5 bytes
    # This patch expects a source file of 11 bytes (11 -> 0x8B)
    # We expect error here
    patch = b"BPS1" + b"\x8B\x8B\x80" + (b"\x00" * 12)
    with pytest.raises(ValueError, match="Source file size mismatch"):
        apply_bps(source, patch)

def test_bps_source_crc_mismatch():
    source = b"HELLO EVERY" # Correct length (11) but wrong content
    target = b"HELLO THERE"
    
    # This patch is valid for the correct source HELLO WORLD
    # When applied to our invalid source, the CRC must fail
    patch_body = b"\x14" + b"\x11" + b"THERE"
    patch = b"BPS1" + b"\x8B\x8B\x80" + patch_body
    # Use CRC of correct source
    patch += zlib.crc32(b"HELLO WORLD").to_bytes(4, "little")
    patch += zlib.crc32(target).to_bytes(4, "little")
    patch += zlib.crc32(patch_body).to_bytes(4, "little")
    
    # Expect error here
    with pytest.raises(ValueError, match="Source file is invalid"):
        apply_bps(source, patch)

