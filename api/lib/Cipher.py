import random
import numpy as np


class Cipher:

    BLOCK_SIZE = 16  # bytes
    KEY_SIZE = 16  # bytes
    ROUNDS = 16

    def __init__(self, key: bytes) -> None:
        self.key = key
        self.subkeys = self.generate_key()

    def encrypt(self, plaintext: bytes, key: bytes, mode: str) -> bytes:

        prev_cipher = None
        if mode in ["cbc", "cfb", "ofb"]:
            # set up IV
            random.seed(int.from_bytes(key, "big"))
            iv = hex(
                int.from_bytes(key[: Cipher.KEY_SIZE // 2], "big")
                + int.from_bytes(key[Cipher.KEY_SIZE // 2 :], "big")
            )[2:].encode()
            prev_cipher = np.frombuffer(
                iv ^ random.getrandbits(len(plaintext), 8), dtype=np.byte
            )
        elif mode == "counter":
            # initial counter
            random.seed(int.from_bytes(key, "big"))
            counter = random.getrandbits(len(plaintext) * 8)

        # init ciphertext
        ciphertext = np.empty(0, dtype=np.byte)

        # padding
        remainder = len(plaintext) % Cipher.BLOCK_SIZE
        if remainder != 0:
            # tambahkan padding agar kelipatan BLOCK_SIZE
            pad_size = Cipher.BLOCK_SIZE - remainder
            plaintext += bytes(pad_size * [pad_size])

        # convert to numpy bytes
        plaintext = np.frombuffer(plaintext, dtype=np.byte)
        key = np.frombuffer(key, dtype=np.byte)

        # enciphering
        for i in range(0, len(plaintext), Cipher.BLOCK_SIZE):
            # init block
            start_index = i * Cipher.BLOCK_SIZE
            # slice
            block = plaintext[start_index : start_index + Cipher.BLOCK_SIZE]
            # XOR kan dengan ciphertext sebelumnya bila mode CBC
            if mode == "cbc":
                block = block ^ prev_cipher
            # initial permutation
            block = self.initial_permutation(block)
            # partisi
            left_block = block[: (Cipher.BLOCK_SIZE // 2)]
            right_block = block[(Cipher.BLOCK_SIZE // 2) :]
            for j in range(Cipher.ROUNDS):
                processed_right = self.f(right_block, self.subkeys[j])
                processed_left = left_block ^ processed_right
                # swap
                left_block = right_block
                right_block = processed_left
            # final permutation
            block = np.concatenate([left_block, right_block])
            block = self.final_permutation(block)
            # ganti prev_cipher
            prev_cipher = block
            # append
            ciphertext = np.append(ciphertext, block)
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key: bytes, mode: str) -> bytes:
        # set up IV
        prev_cipher = None
        if mode in ["cbc", "cfb", "ofb"]:
            # set up IV
            random.seed(int.from_bytes(key, "big"))
            iv = hex(
                int.from_bytes(key[: Cipher.KEY_SIZE // 2], "big")
                + int.from_bytes(key[Cipher.KEY_SIZE // 2 :], "big")
            )[2:].encode()
            prev_cipher = np.frombuffer(
                iv ^ random.getrandbits(len(plaintext), 8), dtype=np.byte
            )
        # init plaintext
        plaintext = np.empty(0, dtype=np.byte)
        # convert to numpy bytes
        ciphertext = np.frombuffer(ciphertext, dtype=np.byte)
        key = np.frombuffer(key, dtype=np.byte)
        # deciphering
        for i in range(0, len(ciphertext), Cipher.BLOCK_SIZE):
            # init block
            start_index = i * Cipher.BLOCK_SIZE
            # slice
            block = ciphertext[start_index : start_index + Cipher.BLOCK_SIZE]
            # inverse final permutation
            block = self.inverse_final_permutation(block)
            # partisi
            left_block = block[: (Cipher.BLOCK_SIZE // 2)]
            right_block = block[(Cipher.BLOCK_SIZE // 2) :]
            for j in range(Cipher.ROUNDS):
                processed_left = self.inv_f(left_block, self.subkeys[j])
                processed_right = right_block ^ processed_left
                # swap
                left_block = processed_right
                right_block = left_block
            block = np.concatenate([left_block, right_block])
            # initial permutation
            block = self.inverse_initial_permutation(block)
            # XOR kan dengan ciphertext sebelumnya bila mode CBC
            if mode == "cbc":
                block = block ^ prev_cipher
            # ganti prev_cipher
            prev_cipher = ciphertext[start_index : start_index + Cipher.BLOCK_SIZE]
            # append
            plaintext = np.append(ciphertext, block)
        # remove padding
        # cek apakah ada padding
        padding_count = plaintext[-1]
        have_padding = True
        for k in range(len(plaintext) - 1, len(plaintext) - padding_count - 1, -1):
            if plaintext[k] != padding_count:
                have_padding = False
                break
        if have_padding:
            # remove padding
            plaintext = plaintext[:-padding_count]
        return bytes(plaintext)

    def generate_key(self) -> list[bytes]:
        subkeys = []
        # key is represented in 4x4 matrix
        key_mtr = np.frombuffer(self.key, dtype=np.uint8).reshape(4, 4)
        base_mtr = key_mtr
        for i in range(1, Cipher.ROUNDS + 1):
            # for j in range of 4, sum all elements in column j
            # then shift all elements in row j by sum * (i+1)
            subkey = np.zeros((4, 4), dtype=np.uint8)
            for j in range(4):
                sum = 0
                for k in range(4):
                    sum += base_mtr[k][j]
                shift = sum * (i + 1)
                # handle case if shift % 4 == 0
                l = 1
                while shift % 4 == 0:
                    shift += i + l
                    l += 1

                shift = shift % 4
                # shift the row based on the number of shift
                subkey[j] = np.roll(base_mtr[j], shift)

            # for each odd iteration, transpose the subkey
            if i % 2 == 1:
                subkey = np.transpose(subkey)
            base_mtr = subkey

            # return subkeys to its original form which is bytes
            subkey = bytes(subkey.reshape(16))
            subkeys.append(subkey)
        return subkeys

    def initial_permutation(self, plaintext: np.ndarray) -> np.ndarray:
        # Convert to 4-row matrix
        mat = np.reshape(plaintext, (4, len(plaintext) // 4))
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Transpose
        mat = mat.transpose()
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # For even rows, shift left by n, and for odd rows, shift right by n
        # BEWARE! Index starts at 0, not 1!
        for i in range(0, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        for i in range(1, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        # Transpose
        mat = mat.transpose()
        # For even rows, shift left by n, and for odd rows, shift right by n
        # BEWARE! Index starts at 0, not 1!
        for i in range(0, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        for i in range(1, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        # Flatten matrix
        permutated = np.ravel(mat)
        return permutated

    def inverse_initial_permutation(self, plaintext: np.ndarray) -> np.ndarray:
        # Convert to 4-row matrix
        mat = np.reshape(plaintext, (4, len(plaintext) // 4))
        # For even rows, shift right by n, and for odd rows, shift left by n
        # BEWARE! Index starts at 0, not 1!
        for i in range(0, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        for i in range(1, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        # Transpose
        mat = mat.transpose()
        # For even rows, shift right by n, and for odd rows, shift left by n
        # BEWARE! Index starts at 0, not 1!
        for i in range(0, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        for i in range(1, len(mat), 2):
            shift = (i // 2) + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Transpose
        mat = mat.transpose()
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Flatten matrix
        unpermutated = np.ravel(mat)
        return unpermutated

    def final_permutation(self, ciphertext: np.ndarray) -> bytes:
        # Convert to 4-row matrix
        mat = np.reshape(ciphertext, (4, len(ciphertext) // 4))
        # Shift right rows by n
        for i in range(0, len(mat)):
            shift = i + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Transpose
        mat = mat.transpose()
        # Shift left rows by n
        for i in range(0, len(mat)):
            shift = i + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Transpose
        mat = mat.transpose()
        # Flatten matrix
        permutated = np.ravel(mat)
        return permutated.tobytes()

    def inverse_final_permutation(self, ciphertext: np.ndarray) -> np.ndarray:
        # Convert to 4-row matrix
        mat = np.reshape(ciphertext, (4, len(ciphertext) // 4))
        # Transpose
        mat = mat.transpose()
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Shift right rows by n
        for i in range(0, len(mat)):
            shift = i + 1
            mat[i] = np.concatenate([mat[i][-shift:], mat[i][:-shift]])
        # Transpose
        mat = mat.transpose()
        # Flip odd rows, BEWARE! Index starts at 0, not 1!
        for i in range(1, len(mat), 2):
            mat[i] = np.flip(mat[i])
        # Shift left rows by n
        for i in range(0, len(mat)):
            shift = i + 1
            mat[i] = np.concatenate([mat[i][shift:], mat[i][:shift]])
        # Flatten matrix
        unpermutated = np.ravel(mat)
        return unpermutated

    def f(self, right_block: np.ndarray, internal_key: np.ndarray) -> np.ndarray:
        expanded_block = self.block_expansion(right_block)
        A = expanded_block ^ internal_key
        B = self.substitute(A)
        return self.permutate(B)

    def inv_f(self, left_block: np.ndarray, internal_key: np.ndarray) -> np.ndarray:
        B = self.inverse_permutate(left_block)
        A = self.inverse_substitute(B)
        original_block = A ^ internal_key
        return self.block_reduction(original_block)

    def block_expansion(self, right_block: np.ndarray) -> np.ndarray:
        # expand right_block dari 8 bytes(64 bit) menjadi 16 bytes(128 bit) (sama kek panjang kunci)
        index = [
            0,
            2,
            4,
            6,
            7,
            6,
            5,
            4,
            3,
            2,
            1,
            0,
            1,
            3,
            5,
            7,
        ]  # byte pertama -> indeks 0
        return np.array([right_block[i] for i in index])

    def block_reduction(self, original_block: np.ndarray) -> np.ndarray:
        # reduksi blok dari 16 bytes menjadi 8 bytes
        return np.array([original_block[-5:-13:-1]])

    def substitute(self, A: np.ndarray) -> np.ndarray:
        # dari expanded key sebanyak 16 bytes (128 bit) menjadi 8 bytes (64 bit)
        # menerima input 8 bit dan menghasilkan 4 bit
        # idenya ada 1 tabel master dan 8 tabel substitusi. 3 bit pertama untuk menentukan tabel subsitusi yang digunakan. 2 bit berikutnya untuk menentukan baris dam 3 bit terakhir untuk menentukan kolom.
        # tabel substitusi berukuran 4x8
        # digenerate dengan menggunakan random.getrandbits(4) dengan seed 420 + n untuk setiap Sn (n dimulai dari 1 untuk S1)
        S1 = [
            [10, 9, 9, 4, 13, 14, 7, 10],
            [7, 4, 5, 8, 13, 13, 7, 6],
            [9, 3, 6, 8, 1, 4, 15, 11],
            [0, 5, 12, 7, 10, 2, 12, 7],
        ]
        S2 = [
            [6, 4, 0, 5, 15, 8, 9, 1],
            [9, 3, 4, 13, 0, 7, 14, 4],
            [12, 14, 2, 0, 7, 5, 8, 12],
            [9, 6, 10, 15, 12, 3, 12, 2],
        ]
        S3 = [
            [5, 2, 8, 10, 12, 12, 14, 11],
            [11, 9, 14, 8, 6, 3, 5, 8],
            [3, 14, 9, 7, 11, 12, 11, 12],
            [14, 4, 13, 9, 14, 11, 1, 9],
        ]
        S4 = [
            [8, 7, 12, 10, 11, 2, 0, 14],
            [11, 10, 6, 1, 3, 14, 2, 0],
            [13, 2, 11, 6, 10, 8, 3, 3],
            [3, 1, 6, 3, 10, 6, 4, 1],
        ]
        S5 = [
            [6, 1, 2, 5, 0, 9, 11, 8],
            [11, 12, 8, 3, 9, 13, 11, 12],
            [3, 9, 10, 5, 6, 13, 8, 8],
            [0, 14, 3, 5, 8, 12, 11, 7],
        ]
        S6 = [
            [2, 5, 11, 11, 5, 1, 3, 14],
            [15, 1, 4, 7, 10, 8, 8, 15],
            [12, 5, 14, 0, 9, 10, 12, 6],
            [11, 4, 13, 15, 4, 5, 7, 5],
        ]
        S7 = [
            [2, 9, 13, 7, 12, 5, 0, 2],
            [4, 1, 10, 11, 14, 0, 8, 11],
            [11, 7, 15, 5, 7, 11, 5, 6],
            [8, 10, 5, 9, 11, 0, 5, 14],
        ]
        S8 = [
            [4, 13, 0, 8, 7, 1, 14, 9],
            [4, 14, 4, 8, 1, 4, 7, 12],
            [1, 9, 14, 6, 9, 2, 15, 0],
            [2, 4, 9, 12, 10, 6, 4, 10],
        ]
        S = [S1,S2,S3,S4,S5,S6,S7,S8]
        #initial block 
        block = np.zeros(8,dtype=np.byte)
        # isi block
        for i in range(Cipher.KEY_SIZE):
            substitute = S[(A[i] & 0xE0)>>5][(A[i] & 0x18)>>3][A[i] & 0x7]
            idx = i//2
            if(i%2==0):
                # indeks genap
                block[idx] = substitute
            else:
                block[idx] = (block[idx]<<4) | substitute
        return block

    def inverse_substitute(self, B: np.ndarray) -> np.ndarray:
        pass

    def permutate(self, B: np.ndarray) -> np.ndarray:
        pass

    def inverse_permutate(self, left_block: np.ndarray) -> np.ndarray:
        pass

if __name__=="__main__":
    c = Cipher(str.encode("abcdefghijklmnop"))
    print(c.substitute(str.encode("qrstuvwxyz012345")).tobytes())