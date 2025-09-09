from PIL import Image

def binary_to_msg(binary_data):
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    message = ""
    for byte in all_bytes:
        if byte == '11111111':  # part of end marker
            continue
        if byte == '11111110':  # last part of end marker
            break
        message += chr(int(byte, 2))
    return message

def decode_image(img_path):
    img = Image.open(img_path)
    img = img.convert("RGBA")

    data = list(img.getdata())
    binary_data = ""

    for pixel in data:
        r, g, b, a = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

    hidden_msg = binary_to_msg(binary_data)
    print("Hidden message extracted:")
    print( hidden_msg)

# Call the decode function
decode_image("encoded_secret_image.png")
