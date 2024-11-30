import streamlit as st
from PIL import Image
import numpy as np
import hashlib
from Crypto.Cipher import AES
import binascii
from io import BytesIO
import os

# ----------------- Encryption Functions ---------------------#

def load_image(file):
    return Image.open(file).convert("RGB")

def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

def generate_secret(size, password):
    # Create a deterministic seed based on the password
    seed = int.from_bytes(hashlib.sha256(password).digest(), 'big') % (2**32)
    np.random.seed(seed)
    
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(0, 256)
            color2 = np.random.randint(0, 256)
            color3 = np.random.randint(0, 256)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x+1, y), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x, y+1), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x+1, y+1), (color1, color2, color3))
    
    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width*2, 2):
        for y in range(0, height*2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x/2), int(y/2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x+1, y), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x, y+1), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x+1, y+1), (color1, color2, color3))
    return ciphered_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x/2), int(y/2)), (color1, color2, color3))
    return new_image

# ------------------------ Encryption -------------------#
def level_one_encrypt(imagename):
    message_image = load_image(imagename)
    size = message_image.size
    width, height = size

    secret_image = generate_secret(size, password=b"secret")
    secret_image.save("secret.jpeg")

    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)
    ciphered_image.save("2-share_encrypt.jpeg")

# -------------------- Construct Encrypted Image  ----------------#
def construct_enc_image(ciphertext, relength, width, height):
    asciicipher = binascii.hexlify(ciphertext).decode('utf-8')
    
    def replace_all(text, dic):
        for i, j in dic.items():
            text = text.replace(i, j)
        return text

    # Replace ascii cipher characters with numbers
    reps = {
        'a':'1', 'b':'2', 'c':'3', 'd':'4', 'e':'5', 'f':'6', 'g':'7',
        'h':'8', 'i':'9', 'j':'10', 'k':'11', 'l':'12', 'm':'13', 'n':'14',
        'o':'15', 'p':'16', 'q':'17', 'r':'18', 's':'19', 't':'20', 'u':'21',
        'v':'22', 'w':'23', 'x':'24', 'y':'25', 'z':'26'
    }
    asciiciphertxt = replace_all(asciicipher, reps)

    # Construct encrypted image
    step = 3
    encimageone = [asciiciphertxt[i:i+step] for i in range(0, len(asciiciphertxt), step)]
    
    # If the last pixel RGB value is less than 3-digits, add a digit '1'
    if len(encimageone[-1]) < 3:
        encimageone[-1] += "1"
    
    # Ensure the length is a multiple of 3 by padding with "101"
    while len(encimageone) % 3 != 0:
        encimageone.append("101")

    encimagetwo = []
    for i in range(0, len(encimageone), step):
        try:
            r = int(encimageone[i])
            g = int(encimageone[i+1])
            b = int(encimageone[i+2])
            encimagetwo.append((r, g, b))
        except IndexError:
            encimagetwo.append((101, 101, 101))  # Default padding

    # Adjust the length to match relength
    encimagetwo = encimagetwo[:relength]

    encim = Image.new("RGB", (int(width), int(height)))
    encim.putdata(encimagetwo)
    encim.save("visual_encrypt.jpeg")

# ------------------------- Visual-encryption -------------------------#
def encrypt_image(imagename, password):
    plaintext = []
    plaintextstr = ""

    im = Image.open(imagename) 
    pix = im.load()

    width, height = im.size
    
    # Break up the image into a list, each with pixel values and then append to a string
    for y in range(height):
        for x in range(width):
            plaintext.append(pix[x, y])

    # Add 100 to each tuple value to make sure each are 3 digits long  
    for pixel in plaintext:
        for value in pixel:
            aa = int(value) + 100
            plaintextstr += str(aa)

    # Length save for encrypted image reconstruction
    relength = len(plaintext)

    # Append dimensions of image for reconstruction after decryption
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"

    # Make sure that plaintextstr length is a multiple of 16 for AES. If not, append "n". 
    while len(plaintextstr) % 16 != 0:
        plaintextstr += "n"

    # Encrypt plaintext
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')  # IV should be bytes
    ciphertext = obj.encrypt(plaintextstr.encode('utf-8'))

    # Write ciphertext to file in binary mode
    cipher_name = imagename + ".crypt"
    with open(cipher_name, 'wb') as g:
        g.write(ciphertext)
    
    construct_enc_image(ciphertext, relength, width, height)
    level_one_encrypt("visual_encrypt.jpeg")
    return "Encryption done....... 2-Share Encryption done.......", ciphertext

# ---------------------- Decryption ---------------------- #
def decrypt_image(ciphername, password):
    # Open secret and ciphered images
    try:
        secret_image = Image.open("secret.jpeg")
        ima = Image.open("2-share_encrypt.jpeg")
    except FileNotFoundError:
        return "Decryption failed. Required secret images not found."

    # Generate the decrypted image
    new_image = generate_image_back(secret_image, ima)
    new_image.save("2-share_decrypt.jpeg")

    # Read ciphertext from file in binary mode
    try:
        with open(ciphername, 'rb') as cipher_file:
            ciphertext = cipher_file.read()
    except FileNotFoundError:
        return "Decryption failed. Ciphertext file not found."

    # Decrypt ciphertext with password
    try:
        obj2 = AES.new(password, AES.MODE_CBC, b'This is an IV456')  # IV should be bytes
        decrypted_bytes = obj2.decrypt(ciphertext)
        decrypted_str = decrypted_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Decryption failed. {str(e)}"

    # Parse the decrypted text back into integer string
    decrypted_str = decrypted_str.replace("n","")

    # Extract dimensions of images
    try:
        height_str = decrypted_str.split("h")[1]
        height = int(height_str.split("w")[0])
        width_str = decrypted_str.split("w")[1]
        width = int(width_str.split("w")[0])
    except (IndexError, ValueError):
        return "Decryption failed. Invalid ciphertext or password."

    # Replace height and width with empty space in decrypted plaintext
    heightr = "h" + str(height) + "h"
    widthr = "w" + str(width) + "w"
    decrypted_str = decrypted_str.replace(heightr, "")
    decrypted_str = decrypted_str.replace(widthr, "")

    # Reconstruct the list of RGB tuples from the decrypted plaintext
    step = 3
    finaltextone = [decrypted_str[i:i+step] for i in range(0, len(decrypted_str), step)]
    finaltexttwo = []
    try:
        for i in range(0, len(finaltextone), step):
            r = int(finaltextone[i]) - 100
            g = int(finaltextone[i+1]) - 100
            b = int(finaltextone[i+2]) - 100
            finaltexttwo.append((r, g, b))
    except (IndexError, ValueError):
        return "Decryption failed. Invalid ciphertext or password."

    # Reconstruct image from list of pixel RGB tuples
    try:
        newim = Image.new("RGB", (int(width), int(height)))
        newim.putdata(finaltexttwo)
        newim.save("visual_decrypt.jpeg")
    except Exception as e:
        return f"Decryption failed during image reconstruction. {str(e)}"

    return "Decryption done.... Visual Decryption done......"

# ---------------------
# Streamlit Interface Starts Here
# ---------------------

st.title("Image Encryption Application")
st.write("**Securely encrypt and decrypt your images using AES and visual encryption techniques.**")

# Password Input
password_input = st.text_input("Enter Encrypt/Decrypt Password:", type="password")

# Tabs for Encryption and Decryption
tab1, tab2 = st.tabs(["🔒 Encrypt Image", "🔓 Decrypt Image"])

with tab1:
    st.header("Encrypt Your Image")
    uploaded_file = st.file_uploader("Choose an image to encrypt", type=["png", "jpg", "jpeg"])
    
    if uploaded_file is not None:
        if password_input == "":
            st.warning("Please enter a password to proceed with encryption.")
        else:
            # Hash the password using SHA-256 to create a 32-byte key
            password_hash = hashlib.sha256(password_input.encode()).digest()
            
            # Save the uploaded image to a temporary file
            temp_image = BytesIO(uploaded_file.read())
            temp_image_path = "temp_upload_image.jpeg"
            with open(temp_image_path, 'wb') as temp_file:
                temp_file.write(temp_image.getvalue())
            
            # Perform encryption
            status, ciphertext = encrypt_image(temp_image_path, password_hash)
            st.success(status)
            
            # Display the encrypted images
            st.subheader("Encrypted Visual Image")
            encrypted_visual = Image.open("visual_encrypt.jpeg")
            st.image(encrypted_visual, use_column_width=True)
            
            # Provide download for ciphertext
            ciphertext_buffer = BytesIO(ciphertext)
            st.download_button(
                label="Download Ciphertext",
                data=ciphertext_buffer,
                file_name="encrypted_image.crypt",
                mime="application/octet-stream"
            )
            
            # Clean up temporary files
            os.remove(temp_image_path)

with tab2:
    st.header("Decrypt Your Image")
    uploaded_cipher = st.file_uploader("Choose the ciphertext file", type=["crypt"])
    
    if uploaded_cipher is not None:
        if password_input == "":
            st.warning("Please enter the password used during encryption.")
        else:
            # Save the uploaded ciphertext to a temporary file
            temp_cipher = BytesIO(uploaded_cipher.read())
            temp_cipher_path = "temp_cipher.crypt"
            with open(temp_cipher_path, 'wb') as temp_file:
                temp_file.write(temp_cipher.getvalue())
            
            # Perform decryption
            status = decrypt_image(temp_cipher_path, hashlib.sha256(password_input.encode()).digest())
            if "failed" not in status.lower():
                st.success(status)
                
                # Display the decrypted image
                st.subheader("Decrypted Image")
                decrypted_image = Image.open("visual_decrypt.jpeg")
                st.image(decrypted_image, use_column_width=True)
                
                # Provide download for decrypted image
                decrypted_buffer = BytesIO()
                decrypted_image.save(decrypted_buffer, format="JPEG")
                st.download_button(
                    label="Download Decrypted Image",
                    data=decrypted_buffer,
                    file_name="decrypted_image.jpeg",
                    mime="image/jpeg"
                )
            else:
                st.error(status)
            
            # Clean up temporary files
            if os.path.exists(temp_cipher_path):
                os.remove(temp_cipher_path)
