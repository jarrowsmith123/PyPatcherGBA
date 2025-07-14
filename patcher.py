import sys
import os
import io
import traceback
import argparse

def read_vli(stream):

    # Takes a stream of vli encoded bits and returns integer value
    # e.g. 0x2C 0x81 returns 300 as an int

    value = 0
    i = 0 # Counter for current bit in byte
    while True:
        byte_data = stream.read(1)
        if not byte_data:
            raise EOFError("Patch file truncated while reading a UPS variable-length integer.")
        byte = byte_data[0]
        
        chunk = byte & 0x7F # Mask out MSB

        if i > 0:
            chunk += 1
        
        value += chunk << (7 * i) # Shift each bit to its correct position base 7
        i += 1
        
        # Terminates when the MBS is 1
        if (byte & 0x80):
            return value

# Patcher Implementations

def apply_ips(rom_path, patch_path, output_path):

    print("Applying IPS patch")
    with open(rom_path, 'rb') as f:
        source_data = f.read()
    
    target_data = bytearray(source_data)
    with open(patch_path, 'rb') as f:
        if f.read(5) != b'PATCH':
            raise ValueError("Invalid IPS patch header")
        while True:
            offset_bytes = f.read(3)
            if offset_bytes == b'EOF':
                break
            if not offset_bytes:
                raise ValueError("IPS patch is truncated - missing EOF marker")
            offset = int.from_bytes(offset_bytes, 'big')
            size = int.from_bytes(f.read(2), 'big')
            if size > 0:
                payload = f.read(size)
                if offset + len(payload) > len(target_data):
                    target_data.extend(b'\x00' * (offset + len(payload) - len(target_data)))
                target_data[offset:offset+size] = payload
            else:
                rle_size = int.from_bytes(f.read(2), 'big')
                rle_byte = f.read(1)
                if offset + rle_size > len(target_data):
                    target_data.extend(b'\x00' * (offset + rle_size - len(target_data)))
                for i in range(rle_size):
                    target_data[offset + i] = rle_byte[0]
    with open(output_path, 'wb') as f:
        f.write(target_data)
    print("Successfully applied IPS patch")

def apply_ups(rom_path, patch_path, output_path):
    print("Applying UPS patch")
    
    with open(rom_path, 'rb') as f:
        source_data = f.read()
    with open(patch_path, 'rb') as f:
        patch_data = f.read()

    patch_stream = io.BytesIO(patch_data)
    if patch_stream.read(4) != b'UPS1':
        raise ValueError("Invalid UPS patch header")

    source_size = read_vli(patch_stream)
    target_size = read_vli(patch_stream)

    patch_body_size = len(patch_data) - 12

    output_data = bytearray(target_size)
    output_data[:len(source_data)] = source_data

    source_pointer = 0
    while patch_stream.tell() < patch_body_size:
        source_pointer += read_vli(patch_stream)
        
        while True:
            patch_byte = patch_stream.read(1)[0]
            if patch_byte == 0:
                break
            if source_pointer < target_size:
                output_data[source_pointer] ^= patch_byte
            source_pointer += 1
        source_pointer += 1

        
    return output_data


def apply_bps(rom_path, patch_path):

    print("Applying BPS patch")
    
    with open(rom_path, 'rb') as f: source_data = f.read()
    with open(patch_path, 'rb') as f: patch_data = f.read()

    patch_stream = io.BytesIO(patch_data)
    if patch_stream.read(4) != b'BPS1':
        raise ValueError("Invalid BPS patch header.")

    source_size = read_vli(patch_stream)
    target_size = read_vli(patch_stream)
    metadata_size = read_vli(patch_stream)
    patch_stream.seek(metadata_size, 1)

    patch_body_size = len(patch_data) - 12

    output_data = bytearray(target_size)
    target_ptr = 0
    source_relative_offset = 0
    target_relative_offset = 0

    # BPS uses a series of commands, not just skip or xor
    while patch_stream.tell() < patch_body_size:
        # A command contains both an action and a length
        command_data = read_vli(patch_stream)
        action = command_data & 0b11 # The action is the last 2 bits
        length = (command_data >> 2) + 1 # The length is the rest of the bits

        # Copy from the original ROM at the current position
        if action == 0:
            chunk = source_data[target_ptr : target_ptr + length]
            output_data[target_ptr : target_ptr + length] = chunk
            target_ptr += length
        # Copy new data directly from the patch file
        elif action == 1:
            chunk = patch_stream.read(length)
            output_data[target_ptr : target_ptr + length] = chunk
            target_ptr += length
        # Copy from the original ROM, but from a different position
        elif action == 2:
            relative_offset_data = read_vli(patch_stream)
            offset = relative_offset_data >> 1
            source_relative_offset += -offset if (relative_offset_data & 1) else offset
            for i in range(length):
                output_data[target_ptr + i] = source_data[source_relative_offset + i]
            source_relative_offset += length
            target_ptr += length
        # Copy from data we've already written to the output file (for repeating patterns)
        elif action == 3:
            relative_offset_data = read_vli(patch_stream)
            offset = relative_offset_data >> 1
            target_relative_offset += -offset if (relative_offset_data & 1) else offset
            for i in range(length):
                output_data[target_ptr + i] = output_data[target_relative_offset + i]
            target_relative_offset += length
            target_ptr += length


    return output_data


def main():
    
    parser = argparse.ArgumentParser(description="A universal ROM patcher for IPS, UPS, and BPS formats.")
    parser.add_argument("rom_path", help="Path to the original ROM file.")
    parser.add_argument("patch_path", help="Path to the patch file (.ips, .ups, .bps).")
    parser.add_argument("-o", "--output", help="Path for the output patched ROM. If not provided, a default name will be used.")
    
    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        OUTPUT_DIR = "output"
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        rom_filename = os.path.basename(args.rom_path)
        name, ext = os.path.splitext(rom_filename)
        output_filename = f"{name}_patched{ext}"
        output_path = os.path.join(OUTPUT_DIR, output_filename)

    print(f"ROM: {args.rom_path}")
    print(f"Patch: {args.patch_path}")
    print(f"Output: {output_path}")
    print("-" * 20)

    try:
        # Read files once
        with open(args.rom_path, 'rb') as f:
            source_data = f.read()
        with open(args.patch_path, 'rb') as f:
            patch_data = f.read()
            
        # Determine patch type
        header = patch_data[:5]
        if header.startswith(b'BPS1'):
            final_data = apply_bps(source_data, patch_data)
        elif header.startswith(b'UPS1'):
            final_data = apply_ups(source_data, patch_data)
        elif header.startswith(b'PATCH'):
            final_data = apply_ips(source_data, patch_data)
        else:
            raise ValueError("Unknown or unsupported patch format. Only IPS, UPS, and BPS are supported.")
            
        # Write the patched file
        with open(output_path, 'wb') as f:
            f.write(final_data)
            
        print("-" * 20)
        print("Patching complete!")

    except FileNotFoundError as e:
        print(f"\nError: File not found - {e.filename}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()