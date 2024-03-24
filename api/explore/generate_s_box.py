def process_six_bits(byte_stream):
    processed_data = []
    current_bit_index = 0
    current_byte_index = 0
    current_byte = byte_stream[current_byte_index]

    while current_byte_index < len(byte_stream):
        # Extract 6 bits from the current byte
        bits = current_byte >> current_bit_index & 0b111111
        processed_data.append(bits)

        # Move to the next byte if we've consumed all 8 bits
        if current_bit_index >= 2:
            current_byte_index += 1
            if current_byte_index < len(byte_stream):
                current_byte = byte_stream[current_byte_index]
            current_bit_index = 0
        else:
            current_bit_index += 6

    return processed_data

# Example byte stream
byte_stream = b'\x9a\xdb'

# Process every 6 bits in the byte stream
processed_data = process_six_bits(byte_stream)

# Print the processed data
print(processed_data)

#DEPRECATED, gak jadi dipakai