import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

class SteganographyApp:
    """Klasa reprezentująca aplikację do ukrywania i wydobywania tekstów w obrazach."""
    def __init__(self, master):
        """Inicjalizacja interfejsu użytkownika aplikacji."""
        self.master = master
        self.master.title("Steganography App")

        self.label = tk.Label(master, text="Tekst do ukrycia:")
        self.label.pack()

        self.text_entry = tk.Text(master, height=5, width=40)
        self.text_entry.pack()

        self.encrypt_var = tk.BooleanVar()
        self.encrypt_checkbox = tk.Checkbutton(master, text="Szyfrowanie", variable=self.encrypt_var)
        self.encrypt_checkbox.pack()

        self.choose_image_button = tk.Button(master, text="Wybierz obraz", command=self.choose_image)
        self.choose_image_button.pack()

        self.hide_button = tk.Button(master, text="Ukryj tekst", command=self.hide_text)
        self.hide_button.pack()

        self.extract_button = tk.Button(master, text="Wydobądź tekst", command=self.extract_text)
        self.extract_button.pack()

        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

        self.image_path = None

    def choose_image(self):
        """Metoda do wyboru obrazu przez użytkownika."""
        self.image_path = filedialog.askopenfilename()
        if self.image_path:
            self.result_label.config(text="Wybrano obraz: " + self.image_path)
    
    def hide_text_in_image(self, image_path, text, iv):
        """Ukrywa tekst w obrazie.

        Args:
            image_path (str): Ścieżka do obrazu.
            text (str): Tekst do ukrycia.
            iv (bytes): Wektor inicjalizacyjny dla szyfrowania.

        Raises:
            FileNotFoundError: Gdy nie można znaleźć pliku obrazu.
        """
        image = Image.open(image_path)
        image_array = np.array(image)

        hash_text = hashlib.sha256(text.encode()).hexdigest()

        binary_text = ''.join(format(ord(char), '08b') for char in hash_text + text)
        binary_text += '1' * (len(image_array.flatten()) - len(binary_text))

        image_array.flags.writeable = True
        for i, bit in enumerate(binary_text):
            image_array.flat[i] = (image_array.flat[i] & ~1) | int(bit)

        stego_image = Image.fromarray(image_array)
        stego_image.save('stego_image.png')

        messagebox.showinfo("Sukces", "Tekst został ukryty w obrazie.")

    def hide_text(self):
        """Ukrywa tekst w wybranym obrazie."""
        text_to_hide = self.text_entry.get("1.0", tk.END).strip()
        if not text_to_hide:
            messagebox.showerror("Błąd", "Proszę wprowadzić tekst do ukrycia.")
            return
        if not self.image_path:
            messagebox.showerror("Błąd", "Proszę wybrać obraz.")
            return

        key = "0123456789abcdef"  # Użyj klucza jako zwykłego ciągu znaków
        iv = secrets.token_bytes(16)
        if self.encrypt_var.get():
            encrypted_text, iv = self.encrypt_text(text_to_hide, key)
            text_to_hide = encrypted_text.hex()

        self.hide_text_in_image(self.image_path, text_to_hide, iv)

    def extract_text(self):
        """Wydobywa tekst ukryty w obrazie."""
        if not self.image_path:
            messagebox.showerror("Błąd", "Proszę wybrać obraz.")
            return

        key = "0123456789abcdef" 

        extracted_text = self.extract_text_from_image(self.image_path, key)
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, extracted_text)

    def encrypt_text(self, text, key):
        """Szyfruje tekst za pomocą algorytmu AES w trybie CBC.

        Args:
            text (str): Tekst do zaszyfrowania.
            key (str): Klucz szyfrujący.

        Returns:
            bytes: Zaszyfrowany tekst.
            bytes: Wektor inicjalizacyjny dla szyfrowania.
        """
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
        iv = cipher.iv
        return ct_bytes, iv

    def decrypt_text(self, ct_bytes, iv, key):
        """Deszyfruje zaszyfrowany tekst za pomocą algorytmu AES w trybie CBC.

        Args:
            ct_bytes (bytes): Zaszyfrowany tekst.
            iv (bytes): Wektor inicjalizacyjny dla szyfrowania.
            key (str): Klucz szyfrujący.

        Returns:
            str: Odszyfrowany tekst.
        """
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct_bytes)
        return unpad(pt, AES.block_size).decode()

    def extract_text_from_image(self, image_path, key):
        """Wydobywa ukryty tekst z obrazu.

        Args:
            image_path (str): Ścieżka do obrazu.
            key (str): Klucz szyfrujący.

        Returns:
            str: Wydobyty tekst.
        """
        image = Image.open(image_path)
        image_array = np.array(image)

        extracted_bits = ''
        for bit in image_array.flatten():
            extracted_bits += str(bit & 1)

        end_index = extracted_bits.find('11111111')
        binary_text = extracted_bits[:end_index]

        hash_text = binary_text[:256]
        text_to_extract = binary_text[256:end_index]

        if key:
            decrypted_text = self.decrypt_text(bytes.fromhex(text_to_extract), bytes.fromhex(hash_text), key)
            return decrypted_text
        else:
            return bytes.fromhex(text_to_extract).decode()


def main():
    """Funkcja uruchamiająca aplikację."""
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
