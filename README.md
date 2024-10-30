                                                                                                                  AES-256 Encryption and Decryption in Go
                                                                                                                  
  This package implements text encryption and decryption using AES-256 algorithm in CFB (Cipher Feedback Mode).The code is written in Go language and includes functions for key generation, text encryption and ciphertext decryption.
A buffer pool is also used to optimise performance.

  Functions:  
1)Encrypt: Encrypts the given plaintext using AES-256. Returns the encrypted ciphertext and the key used for encryption.
2)Decrypt: Decrypts the given ciphertext using AES-256. Returns the decrypted plaintext.


  Variables:
errCiphertextTooShort: An error that occurs if the ciphertext is too short.
bufferPool: A pool of buffers to optimise performance.

  Encryption:
Use the Encrypt function to encrypt text. It accepts a string of plaintext and returns the encrypted ciphertext in base64 format and the key used for encryption.

  Decryption:
To decrypt the text, use the Decrypt function. It accepts a base64 encrypted ciphertext and the key used for encryption and returns the decrypted plaintext.
