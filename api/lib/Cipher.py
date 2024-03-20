import numpy as np
class Cipher():
  BLOCK_SIZE = 64
  ROUNDS = 16
  def __init__(self) -> None:
    pass
  def encrypt(self,plaintext:bytes,key:bytes,mode:str)->bytes:
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
      #initial permutation
      block = self.initial_permutation(block)
      # partisi
      left_block =  block[:(Cipher.BLOCK_SIZE//2)]
      right_block = block[(Cipher.BLOCK_SIZE//2):]
      for j in range(Cipher.ROUNDS):
        internal_key = self.generate_key(j)
        processed_right = self.f(right_block,internal_key)
        processed_left = left_block ^ processed_right
        # swap 
        left_block = right_block
        right_block = processed_left
      #final permutation
      block = np.concatenate([left_block,right_block])
      block = self.final_permutation(block)
      #append
      ciphertext = np.append(ciphertext,block)
    return bytes(ciphertext)
  
  def decrypt(self,ciphertext:bytes,key:bytes,mode:str)->bytes:
    #init plaintext
    plaintext = np.empty(0,dtype=np.byte)
    # convert to numpy bytes
    ciphertext = np.frombuffer(ciphertext,dtype=np.byte)
    key = np.frombuffer(key,dtype=np.byte)
    # init internal key
    self.init_internal_key(key)
    #deciphering
    for i in range(0,len(plaintext),Cipher.BLOCK_SIZE):
      #init block
      start_index = i*Cipher.BLOCK_SIZE
      # slice
      block = plaintext[start_index:start_index + Cipher.BLOCK_SIZE]
      #inverse final permutation
      block = self.inverse_final_permutation(block)
      # partisi
      left_block =  block[:(Cipher.BLOCK_SIZE//2)]
      right_block = block[(Cipher.BLOCK_SIZE//2):]
      for j in range(Cipher.ROUNDS):
        internal_key = self.generate_key(Cipher.ROUNDS-j-1)
        processed_left = self.inv_f(left_block,internal_key)
        processed_right = right_block ^ processed_left
        # swap 
        left_block = processed_right
        right_block = left_block
      block = np.concatenate([left_block,right_block])
      #initial permutation
      block = self.inverse_initial_permutation(block)
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

  def generate_key(self,iteration:int)->np.ndarray[np.byte]:
    pass
  def initial_permutation(self,plaintext:np.ndarray[np.byte])->np.ndarray[np.byte]:
    pass
  def inverse_initial_permutation(self,plaintext:np.ndarray[np.byte])->np.ndarray[np.byte]:
    pass
  def final_permutation(self,ciphertext:np.ndarray[np.byte])->bytes:
    pass
  def inverse_final_permutation(self,ciphertext:np.ndarray[np.byte])->np.ndarray[np.byte]:
    pass
  def init_internal_key(self,key:np.ndarray[np.byte])->None:
    pass
  def f(self,right_block:np.ndarray[np.byte],internal_key:np.ndarray[np.byte])->np.ndarray[np.byte]:
    pass
  def inv_f(self,left_block:np.ndarray[np.byte],internal_key:np.ndarray[np.byte])->np.ndarray[np.byte]:
    pass