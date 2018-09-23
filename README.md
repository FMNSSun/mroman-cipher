# MRoman's Cipher

This cipher has the following properties:

 * Ciphertexts of the same plaintext always have a different length. This makes it hard to correlate ciphertexts with plaintexts based on lengths.
 * Ciphertexts contain random bytes at random locations. This makes it hard to correlate locations of bytes in the plaintext with locations of bytes in the ciphertext.
 * Ciphertexts of the same plaintext always look different. This is achieved through an IV. This makes it hard to tell whether two ciphertexts contain the same plaintext. The IV is additionally encrypted. 
 * The key is internally hashed such that the key length is always 512 bits.
 * It's security is entirely unknown. 
 * It's based on a hash function. The hash function used should be a secure one. The cipher works with any hash function that produces 512 bits hashes.