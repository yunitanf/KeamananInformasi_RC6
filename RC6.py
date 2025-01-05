class RC6:
    def __init__(self, key):
        self.w = 32  # Ukuran kata dalam bit
        self.r = 20  # Jumlah putaran
        self.b = len(key)  # Panjang kunci dalam byte
        self.t = 2 * (self.r + 2)  # Jumlah elemen dalam tabel kunci S
        self.S = [0] * self.t  # Tabel kunci S
        self.key_expansion(key)

    def key_expansion(self, key):
        P_w = 0xB7E15163  # Konstanta P_w
        Q_w = 0x9E3779B9  # Konstanta Q_w

        # Inisialisasi tabel kunci S
        self.S[0] = P_w
        for i in range(1, self.t):
            self.S[i] = (self.S[i - 1] + Q_w) & 0xFFFFFFFF

        # Mengubah kunci menjadi array L
        L = [0] * ((self.b + 3) // 4)
        for i in range(self.b):
            L[i // 4] = (L[i // 4] << 8) | key[i]

        # Mengisi tabel S dengan kunci
        A = B = 0
        i = j = 0
        for k in range(3 * max(self.t, len(L))):
            A = self.S[i] = (self.S[i] + A + B) & 0xFFFFFFFF
            B = L[j] = (L[j] + A + B) & 0xFFFFFFFF
            i = (i + 1) % self.t
            j = (j + 1) % len(L)

    def encrypt(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes long.")

        # Memecah plaintext menjadi 4 kata 32-bit
        A = (plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3]
        B = (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7]
        C = (plaintext[8] << 24) | (plaintext[9] << 16) | (plaintext[10] << 8) | plaintext[11]
        D = (plaintext[12] << 24) | (plaintext[13] << 16) | (plaintext[14] << 8) | plaintext[15]

        # Enkripsi
        B = (B + self.S[0]) & 0xFFFFFFFF
        D = (D + self.S[1]) & 0xFFFFFFFF

        for i in range(1, self.r + 1):
            t = (B * (2 * B + 1)) & 0xFFFFFFFF
            t = ((t << 16) | (t >> (32 - 16))) & 0xFFFFFFFF
            t = (t + self.S[2 * i]) & 0xFFFFFFFF

            u = (D * (2 * D + 1)) & 0xFFFFFFFF
            u = ((u << 16) | (u >> (32 - 16))) & 0xFFFFFFFF
            u = (u + self.S[2 * i + 1]) & 0xFFFFFFFF

            A = (A ^ t) & 0xFFFFFFFF
            C = (C ^ u) & 0xFFFFFFFF
            A, B, C, D = B, C, D, A  # Rotasi

        A = (A + self.S[2 * self.r + 2]) & 0xFFFFFFFF
        C = (C + self.S[2 * self.r + 3]) & 0xFFFFFFFF

        # Menggabungkan hasil enkripsi menjadi byte
        return bytes([
            (A >> 24) & 0xFF, (A >> 16) & 0xFF, (A >> 8) & 0xFF, A & 0xFF,
                        (B >> 24) & 0xFF, (B >> 16) & 0xFF, (B >> 8) & 0xFF, B & 0xFF,
            (C >> 24) & 0xFF, (C >> 16) & 0xFF, (C >> 8) & 0xFF, C & 0xFF,
            (D >> 24) & 0xFF, (D >> 16) & 0xFF, (D >> 8) & 0xFF, D & 0xFF
        ])

    def decrypt(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext must be 16 bytes long.")

        # Memecah ciphertext menjadi 4 kata 32-bit
        A = (ciphertext[0] << 24) | (ciphertext[1] << 16) | (ciphertext[2] << 8) | ciphertext[3]
        B = (ciphertext[4] << 24) | (ciphertext[5] << 16) | (ciphertext[6] << 8) | ciphertext[7]
        C = (ciphertext[8] << 24) | (ciphertext[9] << 16) | (ciphertext[10] << 8) | ciphertext[11]
        D = (ciphertext[12] << 24) | (ciphertext[13] << 16) | (ciphertext[14] << 8) | ciphertext[15]

        # Dekripsi
        C = (C - self.S[2 * self.r + 3]) & 0xFFFFFFFF
        A = (A - self.S[2 * self.r + 2]) & 0xFFFFFFFF

        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C  # Rotasi terbalik
            u = (D * (2 * D + 1)) & 0xFFFFFFFF
            u = ((u << 16) | (u >> (32 - 16))) & 0xFFFFFFFF
            u = (u + self.S[2 * i + 1]) & 0xFFFFFFFF

            t = (B * (2 * B + 1)) & 0xFFFFFFFF
            t = ((t << 16) | (t >> (32 - 16))) & 0xFFFFFFFF
            t = (t + self.S[2 * i]) & 0xFFFFFFFF

            C = (C ^ u) & 0xFFFFFFFF
            A = (A ^ t) & 0xFFFFFFFF

            D = (D - self.S[2 * i]) & 0xFFFFFFFF
            B = (B - self.S[2 * i - 1]) & 0xFFFFFFFF

        D = (D - self.S[1]) & 0xFFFFFFFF
        B = (B - self.S[0]) & 0xFFFFFFFF

        # Menggabungkan hasil dekripsi menjadi byte
        return bytes([
            (A >> 24) & 0xFF, (A >> 16) & 0xFF, (A >> 8) & 0xFF, A & 0xFF,
            (B >> 24) & 0xFF, (B >> 16) & 0xFF, (B >> 8) & 0xFF, B & 0xFF,
            (C >> 24) & 0xFF, (C >> 16) & 0xFF, (C >> 8) & 0xFF, C & 0xFF,
            (D >> 24) & 0xFF, (D >> 16) & 0xFF, (D >> 8) & 0xFF, D & 0xFF
        ])

# Contoh penggunaan
if __name__ == "__main__":
    key = b"0123456789ABCDEF"  # Kunci 128-bit
    plaintext = b"Hello, World!!!"  # Pastikan ini adalah 16 byte

    # Jika plaintext kurang dari 16 byte, tambahkan padding
    if len(plaintext) < 16:
        plaintext += b'\x00' * (16 - len(plaintext))  # Padding dengan nol

    rc6 = RC6(key)
    ciphertext = rc6.encrypt(plaintext)
    print("Ciphertext:", ciphertext.hex())

    decrypted = rc6.decrypt(ciphertext)
    print("Decrypted:", decrypted)

    # Contoh implementasi sederhana dari RC6
# Ini adalah contoh yang sangat dasar dan tidak lengkap.
# Untuk penggunaan nyata, gunakan pustaka kriptografi yang sudah ada.

def generate_key_table(key):
    # Fungsi untuk menghasilkan tabel kunci dari kunci
    # Ini adalah placeholder; implementasi sebenarnya lebih kompleks
    return [0] * 44  # Misalnya, untuk RC6 dengan 4 putaran

def rotate_right(value, shift, bits=32):
    return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

def decrypt_block(block, key_table):
    # Fungsi untuk mendekripsi satu blok
    # Ini adalah placeholder; implementasi sebenarnya lebih kompleks
    return block  # Kembalikan blok yang sama untuk contoh ini

def rc6_decrypt(ciphertext, key):
    # 1. Persiapkan tabel kunci dari kunci
    key_table = generate_key_table(key)

    # 2. Bagi ciphertext menjadi blok
    # Misalnya, kita anggap ciphertext adalah list dari integer 32-bit
    plaintext = []
    for block in ciphertext:
        decrypted_block = decrypt_block(block, key_table)
        plaintext.append(decrypted_block)

    # 3. Kembalikan plaintext
    return plaintext

# Contoh penggunaan
if __name__ == "__main__":
    # Ciphertext yang ingin didekripsi (contoh)
    ciphertext = [0x12345678, 0x9abcdef0]  # Contoh blok ciphertext
    key = [0x0f0e0d0c, 0x0b0a0908, 0x07060504, 0x03020100]  # Contoh kunci

    plaintext = rc6_decrypt(ciphertext, key)
    print("Plaintext:", plaintext)