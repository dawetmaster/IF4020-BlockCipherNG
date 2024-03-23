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
        pass

    def inverse_final_permutation(self, ciphertext: np.ndarray) -> np.ndarray:
        pass

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
        # menerima input 8 bit (2 bytes) dan menghasilkan 4 bit(1 byte)
        # 2 bit buat geser S-box, 6 bit sisanya buat tentuin row dan kolom (sama kek DES)
        S1 = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ]
        S2 = [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ]
        S3 = [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ]
        S4 = [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ]
        S5 = [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ]
        S6 = [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ]
        S7 = [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ]
        S8 = [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
        S = [S1, S2, S3, S4, S5, S6, S7, S8]
        # initial block
        block = np.zeros(8, dtype=np.byte)
        # isi block
        for i in range(Cipher.KEY_SIZE):
            substitute = S[(i + (A[i] & 0xC0))%8][A[i] & 0x21][A[i] & 0x1E]
            idx = i // 2
            if i % 2 == 0:
                # indeks genap
                block[idx] = substitute
            else:
                block[idx] = (block[idx] << 4) | substitute
        return block

    def inverse_substitute(self, B: np.ndarray) -> np.ndarray:
        pass

    def permutate(self, B: np.ndarray) -> np.ndarray:
        pass

    def inverse_permutate(self, left_block: np.ndarray) -> np.ndarray:
        pass


if __name__ == "__main__":
    c = Cipher(str.encode("abcdefghijklmnop"))
    print(c.substitute(str.encode("qrstuvwxyz012345")).tobytes())
