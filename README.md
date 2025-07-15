# PyPatcherGBA

A simple command-line tool and Python library to apply IPS, UPS, and BPS ROM patches.

## Installation

```bash
pip install pypatchergba
```

# Usage
## Command-Line
Apply a patch:
```bash
pypatchergba "my_rom.gba" "my_patch.ips"
```
Specify an output file:
```bash
pypatchergba "my_rom.gba" "my_patch.bps" -o "patched_rom.gba"
```
## As a Python Library
You can also import and use the patcher in your own Python scripts.
```python
import pypatchergba

# Patch from file paths
patched_data = pypatchergba.apply_patch("my_rom.gba", "my_patch.ups")

# Write the new file
with open("new_rom.gba", "wb") as f:
    f.write(patched_data)

print("Patching complete!")
```
## License
This project is licensed under the Apache License 2.0. See the LICENSE file for details.
