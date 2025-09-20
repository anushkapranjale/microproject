import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

# Binary → String conversion
def binary_to_msg(binary_data):
    chars = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if byte == '11111110':  # End marker
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

# Decode function
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

    # Convert to message
    message = binary_to_msg(binary_data)
    return message

# File upload handler
def upload_and_check():
    file_path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
    )
    if not file_path:
        return
    
    try:
        hidden_msg = decode_image(file_path)
        if hidden_msg:
            messagebox.showinfo("Hidden Message Found ✅", f"📩 {hidden_msg}")
        else:
            messagebox.showwarning("No Hidden Data ❌", "No hidden message found in this image.")
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")

# Tkinter GUI
root = tk.Tk()
root.title("🔍 Steganography Checker")
root.geometry("400x200")

label = tk.Label(root, text="Upload an image to check hidden message", font=("Arial", 12))
label.pack(pady=20)

btn = tk.Button(root, text="📂 Upload Image", command=upload_and_check, font=("Arial", 12), bg="lightblue")
btn.pack(pady=10)

root.mainloop()

