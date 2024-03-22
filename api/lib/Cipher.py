import random
import numpy as np
class Cipher():

  BLOCK_SIZE = 16 #bytes
  KEY_SIZE=16 #bytes
  ROUNDS = 16

  def __init__(self, key:bytes) -> None:
    self.key = key
    self.subkeys = self.generate_key()

  def encrypt(self,plaintext:bytes,key:bytes,mode:str)->bytes:

    prev_cipher = None
    if(mode in ["cbc","cfb","ofb"]):
      #set up IV
      iv = hex(int.from_bytes(key[:Cipher.KEY_SIZE//2],"big") + int.from_bytes(key[Cipher.KEY_SIZE//2:],"big"))[2:].encode()
      prev_cipher = np.frombuffer(iv, dtype=np.byte) 
    elif (mode == "counter"):
      # initial counter
      random.seed(int.from_bytes(key, "big"))
      counter = random.getrandbits(len(plaintext) * 8)

    #init ciphertext
    ciphertext = np.empty(0,dtype=np.byte)

    #padding
    remainder = len(plaintext) % Cipher.BLOCK_SIZE
    if remainder != 0:
      # tambahkan padding agar kelipatan BLOCK_SIZE
      pad_size = Cipher.BLOCK_SIZE-remainder
      plaintext += bytes(pad_size * [pad_size])

    # convert to numpy bytes
    plaintext = np.frombuffer(plaintext,dtype=np.byte)
    key = np.frombuffer(key,dtype=np.byte)

    # init internal key
    self.init_internal_key(key)

    #enciphering
    for i in range(0,len(plaintext),Cipher.BLOCK_SIZE):
      #init block
      start_index = i*Cipher.BLOCK_SIZE
      # slice
      block = plaintext[start_index:start_index + Cipher.BLOCK_SIZE]
      # XOR kan dengan ciphertext sebelumnya bila mode CBC
      if(mode=='cbc'):
        block = block ^ prev_cipher
      #initial permutation
      block = self.initial_permutation(block)
      # partisi
      left_block =  block[:(Cipher.BLOCK_SIZE//2)]
      right_block = block[(Cipher.BLOCK_SIZE//2):]
      for j in range(Cipher.ROUNDS):
        processed_right = self.f(right_block,self.subkeys[j])
        processed_left = left_block ^ processed_right
        # swap 
        left_block = right_block
        right_block = processed_left
      #final permutation
      block = np.concatenate([left_block,right_block])
      block = self.final_permutation(block)
      # ganti prev_cipher
      prev_cipher = block
      #append
      ciphertext = np.append(ciphertext,block)
    return bytes(ciphertext)
  
  def decrypt(self,ciphertext:bytes,key:bytes,mode:str)->bytes:
    #set up IV
    prev_cipher = None
    if(mode=="cbc"):
      iv = hex(int.from_bytes(key[:Cipher.KEY_SIZE//2],"big") + int.from_bytes(key[Cipher.KEY_SIZE//2:],"big"))[2:].encode()
      prev_cipher = np.frombuffer(iv,dtype=np.byte) 
    #init plaintext
    plaintext = np.empty(0,dtype=np.byte)
    # convert to numpy bytes
    ciphertext = np.frombuffer(ciphertext,dtype=np.byte)
    key = np.frombuffer(key,dtype=np.byte)
    # init internal key
    self.init_internal_key(key)
    #deciphering
    for i in range(0,len(ciphertext),Cipher.BLOCK_SIZE):
      #init block
      start_index = i*Cipher.BLOCK_SIZE
      # slice
      block = ciphertext[start_index:start_index + Cipher.BLOCK_SIZE]
      #inverse final permutation
      block = self.inverse_final_permutation(block)
      # partisi
      left_block =  block[:(Cipher.BLOCK_SIZE//2)]
      right_block = block[(Cipher.BLOCK_SIZE//2):]
      for j in range(Cipher.ROUNDS):
        processed_left = self.inv_f(left_block,self.subkeys[j])
        processed_right = right_block ^ processed_left
        # swap 
        left_block = processed_right
        right_block = left_block
      block = np.concatenate([left_block,right_block])
      #initial permutation
      block = self.inverse_initial_permutation(block)
      # XOR kan dengan ciphertext sebelumnya bila mode CBC
      if(mode=='cbc'):
        block = block ^ prev_cipher
      # ganti prev_cipher
      prev_cipher = ciphertext[start_index:start_index + Cipher.BLOCK_SIZE]
      #append
      plaintext = np.append(ciphertext,block)
    #remove padding
    # cek apakah ada padding
    padding_count = plaintext[-1]
    have_padding = True
    for k in range(len(plaintext)-1,len(plaintext)-padding_count-1,-1):
      if(plaintext[k]!=padding_count):
        have_padding = False
        break
    if have_padding:
      # remove padding
      plaintext = plaintext[:-padding_count]
    return bytes(plaintext)

  def generate_key(self)->list[bytes]:
    subkeys = []
    # key is represented in 4x4 matrix
    key_mtr = np.frombuffer(self.key, dtype=np.uint8).reshape(4,4)
    base_mtr = key_mtr
    for i in range(1, Cipher.ROUNDS + 1):
      # for j in range of 4, sum all elements in column j
      # then shift all elements in row j by sum * (i+1)
      subkey = np.zeros((4,4),dtype=np.uint8)
      for j in range(4):
        sum = 0
        for k in range(4):
          sum += base_mtr[k][j]
        shift = sum * (i+1)
        # handle case if shift % 4 == 0
        l = 1
        while shift % 4 == 0:
          shift += i+l
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


  def initial_permutation(self,plaintext:np.ndarray)->np.ndarray:
    pass
  def inverse_initial_permutation(self,plaintext:np.ndarray)->np.ndarray:
    pass
  def final_permutation(self,ciphertext:np.ndarray)->bytes:
    pass
  def inverse_final_permutation(self,ciphertext:np.ndarray)->np.ndarray:
    pass
  def init_internal_key(self,key:np.ndarray)->None:
    pass
  def f(self,right_block:np.ndarray,internal_key:np.ndarray)->np.ndarray:
    pass
  def inv_f(self,left_block:np.ndarray,internal_key:np.ndarray)->np.ndarray:
    pass
