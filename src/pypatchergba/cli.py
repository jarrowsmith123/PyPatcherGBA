import argparse
import os
import sys
import traceback
from .patcher import apply_patch

def main():

    parser = argparse.ArgumentParser(description="A universal ROM patcher for IPS, UPS, and BPS formats.")
    parser.add_argument("rom_path", help="Path to the original ROM file.")
    parser.add_argument("patch_path", help="Path to the patch file (.ips, .ups, .bps).")
    parser.add_argument("-o", "--output", help="Path for the output patched ROM. If not provided, a default name will be used.")
    
    args = parser.parse_args()

    if args.output:
        output_path = args.output
    else:
        OUTPUT_DIR = "output"
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        # Output ROM name will default to hack name + rom extension
        patch_name = os.path.splitext(os.path.basename(args.patch_path))[0]
        rom_ext = os.path.splitext(args.rom_path)[1]
        output_filename = f"{patch_name}{rom_ext}"
        output_path = os.path.join(OUTPUT_DIR, output_filename)


    print(f"ROM: {args.rom_path}")
    print(f"Patch: {args.patch_path}")
    print(f"Output: {output_path}")
    print("-" * 20)

    try:
        print("Applying patch...")
        final_data = apply_patch(args.rom_path, args.patch_path)
        
        with open(output_path, 'wb') as f:
            f.write(final_data)
            
        print("-" * 20)
        print(f"Patching complete! Output saved to: {output_path}")

    except FileNotFoundError as e:
        print(f"\nError: File not found - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()