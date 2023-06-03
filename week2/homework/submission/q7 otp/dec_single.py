print("ha")

# 1. calculate key using default plain text and server response cipher text
default_p = "Student ID 1000000 gets 0 points"
default_c = "0x161d0c56130b17493e2145625800514555596b52140116457942115d2c0b071b"
default_c = default_c[2:]

def xor_strings(plaintext, hex_string):
    # Convert hex string to bytes
    bytes_hex = bytes.fromhex(hex_string)

    # Convert plaintext to bytes
    bytes_plain = plaintext.encode()

    # Perform XOR operation
    result = bytearray(a ^ b for a, b in zip(bytes_plain, bytes_hex))

    # Convert result back to binary string
    xor_result = ''.join(format(byte, '08b') for byte in result)

    return xor_result

def binary_to_hex(binary):
    decimal_value = int(binary, 2)
    hex_value = hex(decimal_value)[2:]  # Remove the '0x' prefix
    return hex_value

otp = xor_strings(default_p, default_c)

# 2. get updated cipher text by otp XOR updated plain text
updated_p = "Student ID 1007399 gets 6 points"
updated_c = xor_strings(updated_p, binary_to_hex(otp))

print("ans:")
print(updated_c)

print(binary_to_hex(updated_c))