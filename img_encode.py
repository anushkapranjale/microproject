from PIL import Image
def msg_to_binary(msg):
    return ''.join(format(ord(char), '08b') for char in msg)
def encode_image(img_path, message, output_path):
    img = Image.open(img_path)
    img = img.convert("RGBA")  # tu ne bola image RGBA hai

    data = list(img.getdata())
    binary_msg = msg_to_binary(message) + '1111111111111110'  # END MARKER
    msg_index = 0
    new_data = []

    for pixel in data:
        r, g, b, a = pixel
        if msg_index < len(binary_msg):
            r = r & ~1 | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            g = g & ~1 | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            b = b & ~1 | int(binary_msg[msg_index])
            msg_index += 1
        new_data.append((r, g, b, a))

    encoded_img = Image.new(img.mode, img.size)
    encoded_img.putdata(new_data)
    encoded_img.save(output_path)
    print("✅ Secret message successfully hidden in image!")

encode_image(
    r"C:\Users\DELL\OneDrive\Pictures\Screenshots\example.png",
    "Hello",
    "encoded_secret_image.png"
)
