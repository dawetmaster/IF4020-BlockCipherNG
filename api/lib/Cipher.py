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
                iv ^ random.getrandbits(len(plaintext), 8), dtype=np.uint8
            )
        elif mode == "counter":
            # initial counter
            random.seed(int.from_bytes(key, "big"))
            counter = random.getrandbits(len(plaintext) * 8)

        # init ciphertext
        ciphertext = np.empty(0, dtype=np.uint8)

        # padding
        remainder = len(plaintext) % Cipher.BLOCK_SIZE
        if remainder != 0:
            # tambahkan padding agar kelipatan BLOCK_SIZE
            pad_size = Cipher.BLOCK_SIZE - remainder
            plaintext = plaintext[:] +  bytes(pad_size * [pad_size])

        # convert to numpy bytes
        plaintext = np.frombuffer(plaintext, dtype=np.uint8)
        # print(plaintext)
        key = np.frombuffer(key, dtype=np.uint8)

        # enciphering
        for i in range(len(plaintext)//Cipher.BLOCK_SIZE):
            # init block
            start_index = i * Cipher.BLOCK_SIZE
            # slice
            block = plaintext[start_index : start_index + Cipher.BLOCK_SIZE]
            # print(block)
            # XOR kan dengan ciphertext sebelumnya bila mode CBC
            if mode == "cbc":
                block = block ^ prev_cipher
            # initial permutation
            block = self.initial_permutation(block)
            # partisi
            left_block = block[: (Cipher.BLOCK_SIZE // 2)]
            right_block = block[(Cipher.BLOCK_SIZE // 2) :]
            for j in range(Cipher.ROUNDS):
                # processed_right = self.f(right_block, self.subkeys[j])
                # processed_left = left_block ^ processed_right
                # bit permutation
                block = self.initial_permutation(block)
                #xor plainteks dengan key
                subkey = np.frombuffer(self.subkeys[j],dtype=np.uint8)
                block = self.f(block,subkey )
                # block = processed_block ^ (np.concatenate(right_block,left_block))
                left_block = block[: (Cipher.BLOCK_SIZE // 2)]
                right_block = block[(Cipher.BLOCK_SIZE // 2) :]
                # processed_left = (
                #     np.concatenate((right_block, left_block)) ^ processed_block
                # )
                # left_block = processed_block[: (Cipher.BLOCK_SIZE // 2)]
                # right_block = processed_block[(Cipher.BLOCK_SIZE // 2) :]
                # left_block = right_block
                # right_block = processed_left[(Cipher.BLOCK_SIZE // 2) :]
            # final permutation
            # block = np.concatenate([left_block, right_block])
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
                iv ^ random.getrandbits(len(plaintext), 8), dtype=np.uint8
            )
        # init plaintext
        plaintext = np.empty(0, dtype=np.uint8)
        # convert to numpy bytes
        ciphertext = np.frombuffer(ciphertext, dtype=np.uint8)
        key = np.frombuffer(key, dtype=np.uint8)
        # deciphering
        for i in range(len(ciphertext)//Cipher.BLOCK_SIZE):
            # init block
            start_index = i * Cipher.BLOCK_SIZE
            # slice
            block = ciphertext[start_index : start_index + Cipher.BLOCK_SIZE]
            # inverse final permutation
            block = self.inverse_final_permutation(block)
            # partisi
            left_block = block[: (Cipher.BLOCK_SIZE // 2)]
            right_block = block[(Cipher.BLOCK_SIZE // 2) :]
            processed_right = right_block
            for j in range(Cipher.ROUNDS-1,-1,-1):
                subkey = np.frombuffer(self.subkeys[j],dtype=np.uint8)
                # swap
                # left_block = processed_block[: (Cipher.BLOCK_SIZE // 2)]
                # right_block = processed_block[(Cipher.BLOCK_SIZE // 2) :]
                # left_block = processed_right
                # right_block = left_block
                # processed_left = self.inv_f(left_block, self.subkeys[j])
                # processed_right = right_block ^ processed_left
                processed_block = self.inv_f(block, subkey)
                block = processed_block
                # block = self.inverse_final_permutation(block)
                block = self.inverse_initial_permutation(block)
                # processed_right = (
                #     np.concatenate((right_block, left_block)) ^ processed_block
                # )
            # block = np.concatenate([left_block, right_block])
            # initial permutation
            block = self.inverse_initial_permutation(block)
            # XOR kan dengan ciphertext sebelumnya bila mode CBC
            if mode == "cbc":
                block = block ^ prev_cipher
            # ganti prev_cipher
            prev_cipher = ciphertext[start_index : start_index + Cipher.BLOCK_SIZE]
            # append
            # print("b",block)
            plaintext = np.append(plaintext, block)
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
            plaintext = plaintext[:len(plaintext)-padding_count]
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
        # First, convert each element of the plaintext into array of 0's and 1's.
        # Each element of mat will be consisted of an array of 0's and 1's.
        # print("plain enc",plaintext)
        mat = [0 for _ in range(len(plaintext))]
        for i in range(0, len(plaintext)):
            mat[i] = np.asarray([int(i) for i in bin(plaintext[i])[2:].zfill(8)], dtype=np.uint8)
        mat = np.array(mat)
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
        # Convert each mat element to uint8
        permutated = np.packbits(mat)
        # print("perm enc",permutated)
        return permutated

    def inverse_initial_permutation(self, plaintext: np.ndarray) -> np.ndarray:
        # First, convert each element of the plaintext into array of 0's and 1's.
        # Each element of mat will be consisted of an array of 0's and 1's.
        mat = [0 for _ in range(len(plaintext))]
        for i in range(0, len(plaintext)):
            mat[i] = np.asarray([int(i) for i in bin(plaintext[i]).replace("-","")[2:].zfill(8)], dtype=np.uint8)
        mat = np.array(mat)
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
        # Convert each mat element to uint8
        unpermutated = np.packbits(mat)
        return unpermutated

    def final_permutation(self, ciphertext: np.ndarray) -> bytes:
        # First, convert each element of the plaintext into array of 0's and 1's.
        # Each element of mat will be consisted of an array of 0's and 1's.
        mat = [0 for _ in range(len(ciphertext))]
        for i in range(0, len(ciphertext)):
            mat[i] = np.asarray([int(i) for i in bin(ciphertext[i]).replace("-",'')[2:].zfill(8)], dtype=np.uint8)
        mat = np.array(mat)
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
        permutated = np.packbits(mat)
        return permutated.tobytes()

    def inverse_final_permutation(self, ciphertext: np.ndarray) -> np.ndarray:
        # First, convert each element of the plaintext into array of 0's and 1's.
        # Each element of mat will be consisted of an array of 0's and 1's.
        mat = [0 for _ in range(len(ciphertext))]
        for i in range(0, len(ciphertext)):
            mat[i] = np.asarray([int(i) for i in bin(ciphertext[i]).replace("-",'')[2:].zfill(8)], dtype=np.uint8)
        mat = np.array(mat)
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
        # Convert each mat element to uint8
        unpermutated = np.packbits(mat)
        return unpermutated

    def f(self, block: np.ndarray, internal_key: np.ndarray) -> np.ndarray:
        # expanded_block = self.block_expansion(right_block)
        # A = expanded_block ^ internal_key
        A = block ^ internal_key
        B = self.substitute(A)
        return self.permutate(B)

    def inv_f(self, left_block: np.ndarray, internal_key: np.ndarray) -> np.ndarray:
        B = self.inverse_permutate(left_block)
        A = self.inverse_substitute(B)
        original_block = A ^ internal_key
        # return self.block_reduction(original_block)
        return original_block

    def substitute(self, A: np.ndarray) -> np.ndarray:
        # pake S-box AES
        # convert 8 bit -> 8 bit
        # initial block
        block = np.zeros(Cipher.BLOCK_SIZE, dtype=np.uint8)
        S_BOX = [
            [
                0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5, 
                0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
            ],
            [
                0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0, 
                0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
            ],
            [
                0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC, 
                0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
            ],
            [
                0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A, 
                0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
            ],
            [
                0x09,
                0x83,
                0x2C,
                0x1A,
                0x1B,
                0x6E,
                0x5A,
                0xA0,
                0x52,
                0x3B,
                0xD6,
                0xB3,
                0x29,
                0xE3,
                0x2F,
                0x84,
            ],
            [
                0x53,
                0xD1,
                0x00,
                0xED,
                0x20,
                0xFC,
                0xB1,
                0x5B,
                0x6A,
                0xCB,
                0xBE,
                0x39,
                0x4A,
                0x4C,
                0x58,
                0xCF,
            ],
            [
                0xD0,
                0xEF,
                0xAA,
                0xFB,
                0x43,
                0x4D,
                0x33,
                0x85,
                0x45,
                0xF9,
                0x02,
                0x7F,
                0x50,
                0x3C,
                0x9F,
                0xA8,
            ],
            [
                0x51,
                0xA3,
                0x40,
                0x8F,
                0x92,
                0x9D,
                0x38,
                0xF5,
                0xBC,
                0xB6,
                0xDA,
                0x21,
                0x10,
                0xFF,
                0xF3,
                0xD2,
            ],
            [
                0xCD,
                0x0C,
                0x13,
                0xEC,
                0x5F,
                0x97,
                0x44,
                0x17,
                0xC4,
                0xA7,
                0x7E,
                0x3D,
                0x64,
                0x5D,
                0x19,
                0x73,
            ],
            [
                0x60,
                0x81,
                0x4F,
                0xDC,
                0x22,
                0x2A,
                0x90,
                0x88,
                0x46,
                0xEE,
                0xB8,
                0x14,
                0xDE,
                0x5E,
                0x0B,
                0xDB,
            ],
            [
                0xE0,
                0x32,
                0x3A,
                0x0A,
                0x49,
                0x06,
                0x24,
                0x5C,
                0xC2,
                0xD3,
                0xAC,
                0x62,
                0x91,
                0x95,
                0xE4,
                0x79,
            ],
            [
                0xE7,
                0xC8,
                0x37,
                0x6D,
                0x8D,
                0xD5,
                0x4E,
                0xA9,
                0x6C,
                0x56,
                0xF4,
                0xEA,
                0x65,
                0x7A,
                0xAE,
                0x08,
            ],
            [
                0xBA,
                0x78,
                0x25,
                0x2E,
                0x1C,
                0xA6,
                0xB4,
                0xC6,
                0xE8,
                0xDD,
                0x74,
                0x1F,
                0x4B,
                0xBD,
                0x8B,
                0x8A,
            ],
            [
                0x70,
                0x3E,
                0xB5,
                0x66,
                0x48,
                0x03,
                0xF6,
                0x0E,
                0x61,
                0x35,
                0x57,
                0xB9,
                0x86,
                0xC1,
                0x1D,
                0x9E,
            ],
            [
                0xE1,
                0xF8,
                0x98,
                0x11,
                0x69,
                0xD9,
                0x8E,
                0x94,
                0x9B,
                0x1E,
                0x87,
                0xE9,
                0xCE,
                0x55,
                0x28,
                0xDF,
            ],
            [
                0x8C,
                0xA1,
                0x89,
                0x0D,
                0xBF,
                0xE6,
                0x42,
                0x68,
                0x41,
                0x99,
                0x2D,
                0x0F,
                0xB0,
                0x54,
                0xBB,
                0x16,
            ],
        ]
        for i in range(Cipher.KEY_SIZE):
            row = (A[i] & 0xF0)>>4
            column = A[i] & 0x0F
            block[i] = S_BOX[row][column]
        return block

    def inverse_substitute(self, B: np.ndarray) -> np.ndarray:
        block = np.zeros(Cipher.BLOCK_SIZE, dtype=np.uint8)
        INV_S_BOX = [
            [
                0x52,
                0x09,
                0x6A,
                0xD5,
                0x30,
                0x36,
                0xA5,
                0x38,
                0xBF,
                0x40,
                0xA3,
                0x9E,
                0x81,
                0xF3,
                0xD7,
                0xFB,
            ],
            [
                0x7C,
                0xE3,
                0x39,
                0x82,
                0x9B,
                0x2F,
                0xFF,
                0x87,
                0x34,
                0x8E,
                0x43,
                0x44,
                0xC4,
                0xDE,
                0xE9,
                0xCB,
            ],
            [
                0x54,
                0x7B,
                0x94,
                0x32,
                0xA6,
                0xC2,
                0x23,
                0x3D,
                0xEE,
                0x4C,
                0x95,
                0x0B,
                0x42,
                0xFA,
                0xC3,
                0x4E,
            ],
            [
                0x08,
                0x2E,
                0xA1,
                0x66,
                0x28,
                0xD9,
                0x24,
                0xB2,
                0x76,
                0x5B,
                0xA2,
                0x49,
                0x6D,
                0x8B,
                0xD1,
                0x25,
            ],
            [
                0x72,
                0xF8,
                0xF6,
                0x64,
                0x86,
                0x68,
                0x98,
                0x16,
                0xD4,
                0xA4,
                0x5C,
                0xCC,
                0x5D,
                0x65,
                0xB6,
                0x92,
            ],
            [
                0x6C,
                0x70,
                0x48,
                0x50,
                0xFD,
                0xED,
                0xB9,
                0xDA,
                0x5E,
                0x15,
                0x46,
                0x57,
                0xA7,
                0x8D,
                0x9D,
                0x84,
            ],
            [
                0x90,
                0xD8,
                0xAB,
                0x00,
                0x8C,
                0xBC,
                0xD3,
                0x0A,
                0xF7,
                0xE4,
                0x58,
                0x05,
                0xB8,
                0xB3,
                0x45,
                0x06,
            ],
            [
                0xD0,
                0x2C,
                0x1E,
                0x8F,
                0xCA,
                0x3F,
                0x0F,
                0x02,
                0xC1,
                0xAF,
                0xBD,
                0x03,
                0x01,
                0x13,
                0x8A,
                0x6B,
            ],
            [
                0x3A,
                0x91,
                0x11,
                0x41,
                0x4F,
                0x67,
                0xDC,
                0xEA,
                0x97,
                0xF2,
                0xCF,
                0xCE,
                0xF0,
                0xB4,
                0xE6,
                0x73,
            ],
            [
                0x96,
                0xAC,
                0x74,
                0x22,
                0xE7,
                0xAD,
                0x35,
                0x85,
                0xE2,
                0xF9,
                0x37,
                0xE8,
                0x1C,
                0x75,
                0xDF,
                0x6E,
            ],
            [
                0x47,
                0xF1,
                0x1A,
                0x71,
                0x1D,
                0x29,
                0xC5,
                0x89,
                0x6F,
                0xB7,
                0x62,
                0x0E,
                0xAA,
                0x18,
                0xBE,
                0x1B,
            ],
            [
                0xFC,
                0x56,
                0x3E,
                0x4B,
                0xC6,
                0xD2,
                0x79,
                0x20,
                0x9A,
                0xDB,
                0xC0,
                0xFE,
                0x78,
                0xCD,
                0x5A,
                0xF4,
            ],
            [
                0x1F,
                0xDD,
                0xA8,
                0x33,
                0x88,
                0x07,
                0xC7,
                0x31,
                0xB1,
                0x12,
                0x10,
                0x59,
                0x27,
                0x80,
                0xEC,
                0x5F,
            ],
            [
                0x60,
                0x51,
                0x7F,
                0xA9,
                0x19,
                0xB5,
                0x4A,
                0x0D,
                0x2D,
                0xE5,
                0x7A,
                0x9F,
                0x93,
                0xC9,
                0x9C,
                0xEF,
            ],
            [
                0xA0,
                0xE0,
                0x3B,
                0x4D,
                0xAE,
                0x2A,
                0xF5,
                0xB0,
                0xC8,
                0xEB,
                0xBB,
                0x3C,
                0x83,
                0x53,
                0x99,
                0x61,
            ],
            [
                0x17,
                0x2B,
                0x04,
                0x7E,
                0xBA,
                0x77,
                0xD6,
                0x26,
                0xE1,
                0x69,
                0x14,
                0x63,
                0x55,
                0x21,
                0x0C,
                0x7D,
            ],
        ]
        for i in range(Cipher.KEY_SIZE):
            row = (B[i] & 0xF0)>>4
            column = B[i] & 0x0F
            block[i] = INV_S_BOX[row][column]
        return block

    def permutate(self, B: np.ndarray) -> np.ndarray:
        #digenerate dengan python random dengan seed 960024
        P_BOX = [12, 8, 4, 0, 9, 14, 15, 10, 1, 6, 3, 13, 2, 11, 5, 7]
        return np.array([B[P_BOX[i]] for i in range(Cipher.BLOCK_SIZE)],dtype=np.uint8)

    def inverse_permutate(self, left_block: np.ndarray) -> np.ndarray:
        INVERSE_P_BOX = [3, 8, 12, 10, 2, 14, 9, 15, 1, 4, 7, 13, 0, 11, 5, 6]
        return np.array([left_block[INVERSE_P_BOX[i]] for i in range(Cipher.BLOCK_SIZE)],dtype=np.uint8)


if __name__ == "__main__":
    c = Cipher(str.encode("abcdefghijklmnop"))
    # res = c.substitute(np.frombuffer(str.encode("qrstuvwxyz012345"),dtype=np.uint8))

    # tes enkripsi
    #"qrstuAwxyz012345" -> 'L*\x80\xa5q*,6\xc0T&I\x84.@\xe1'
    #"qrstvAwxyz012345" ->b'L"\x04\x85q*,6\xc0T&\t\x84>H\xe3'
    # plaintext = np.frombuffer(str.encode("halohalobandung ibukota pariaman. Sudah laman214uiweofewoiferhi"),dtype=np.uint8)
    plaintext = str.encode("hamohalobandung ibukota pariaman. Sudah laman214uiweofewoiferhi")
    print("plain",bytes(plaintext))
    ciphertext = c.encrypt(plaintext,c.key,'ecb')
    print(f"Ciphertext: {ciphertext}")
    # tes dekripsi
    reverse_plaintext = c.decrypt(ciphertext,c.key,"ecb")
    print(f"PLaintext: {reverse_plaintext}")

    print("PLAINTEKS:",bytes(plaintext))
    print("REVERSED_PLAINTEKS",c.decrypt(c.encrypt(plaintext,c.key,'ecb'),c.key,'ecb'))
    #'R\t\xf8\x03\x1b\x98\xdca_\r\xfa\xda\xfe8\x84\xfd'
    #'R\t\xf8\x03\x1b\x98\xdca[\r\xda\xda~8\x84\xfd'

    #plain b'qrstuAvxyz012365'
    #Ciphertext: b'\xed \xd5 \x91 j \x8e \xc5 ; y z \xf6 k \xff . \xe3 i K'
    #plain b'qrsruAvxyz012365'
    #Ciphertext: b'z \x91 \xdc \x9d \x9b n g \x86 2 \xf4 \x1e 8 \x9b \xbb \xc6 \x1e'

"""
plain b'halohalobandung ibukota pariaman. Sudah laman214uiweofewoiferhi'
Ciphertext: b'S"1:\xb8+,\xed\xf7\x8c\xb3\x17`A\xa5\xb1\xf5\xd6\xe9\xce{V\x1c\x1e\xcc\x80\x1b\xf5\x8e\xac\xcb\xa7j\x92~\xd6\x94\xcf\xcd!\x84\xe0hO\xc3\x15\xece\x1f%4\t\xccF\xef\xbe\xb6\xce^\x14 \x96\x929'
"""
"""
plain b'hamohalobandung ibukota pariaman. Sudah laman214uiweofewoiferhi'
Ciphertext: b':`j\xfcz\x1cc\xb6\xe4\xfc^\xf9\xcb\xf1\xc33\xf5\xd6\xe9\xce{V\x1c\x1e\xcc\x80\x1b\xf5\x8e\xac\xcb\xa7j\x92~\xd6\x94\xcf\xcd!\x84\xe0hO\xc3\x15\xece\x1f%4\t\xccF\xef\xbe\xb6\xce^\x14 \x96\x929'
"""
"""
plain b'halohalobandung ibukota pbriaman. Sudah laman214uiweofewoiferhi'
Ciphertext: b'S"1:\xb8+,\xed\xf7\x8c\xb3\x17`A\xa5\xb1\xed\x0c@\x1f6\xe5\xf73Q\x93\x82\xe7B\'\x9b\x16j\x92~\xd6\x94\xcf\xcd!\x84\xe0hO\xc3\x15\xece\x1f%4\t\xccF\xef\xbe\xb6\xce^\x14 \x96\x929'
"""