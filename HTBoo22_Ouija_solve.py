from binascii import unhexlify
import subprocess

# Define byte sequences to replace
MOV_EDI_1 = unhexlify('bf01000000')
MOV_EDI_10 = unhexlify('bf0a000000')
MOV_EDI_0 = unhexlify('bf00000000')

# Patch the binary
with open('ouija', 'rb') as f:
    orig = f.read()

with open('patched', 'wb') as f:
    f.write(orig.replace(MOV_EDI_1, MOV_EDI_0).replace(MOV_EDI_10, MOV_EDI_0))

# Run the patched binary and capture its output
result = subprocess.run(['./patched'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Check if the command was successful
if result.returncode != 0:
    print("Error running the binary:", result.stderr)
    exit(1)

# Prepare to collect the flag characters
flag_chars = []

# Flag state
capture_next = False

# Process the output line by line
for line in result.stdout.splitlines():
    # Look for '..... done!' to decide whether to capture the next line
    if '..... done!' in line:
        capture_next = True
    elif capture_next:
        # Capture the next line if it's a single character
        if len(line) == 1:
            flag_chars.append(line)
        capture_next = False  # Reset the flag state

# Join the flag characters into a single string
flag = ''.join(flag_chars)

# Print the extracted flag
print("Extracted Flag:", flag)
