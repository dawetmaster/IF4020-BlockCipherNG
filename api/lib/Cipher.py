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
    pass

  def generate_key(self,iteration:int)->np.NDArray[np.byte]:
    pass
  def initial_permutation(self,plaintext:np.NDArray[np.byte])->np.NDArray[np.byte]:
    pass
  def final_permutation(self,ciphertext:np.NDArray[np.byte])->bytes:
    pass
  def init_internal_key(self,key:np.NDArray[np.byte])->None:
    pass
  def f(self,right_block:np.NDArray[np.byte],internal_key:np.NDArray[np.byte])->np.NDArray[np.byte]:
    pass