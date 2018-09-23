# MRoman's Cipher

This cipher has the following properties:

 * Ciphertexts of the same plaintext always have a different length. This makes it hard to correlate ciphertexts with plaintexts based on lengths.
 * Ciphertexts contain random bytes at random locations. This makes it hard to correlate locations of bytes in the plaintext with locations of bytes in the ciphertext.
 * Ciphertexts of the same plaintext always look different. This is achieved through an IV. This makes it hard to tell whether two ciphertexts contain the same plaintext. The IV is additionally encrypted. 
 * The key is internally hashed such that the key length is always 512 bits.
 * Its security is entirely unknown. 
 * It's based on a hash function. The hash function used should be a secure one. The cipher works with any hash function that produces 512 bits hashes.

You should probably only use this if you're paranoid that other algorithms have secret backdoors in it 
but even then... why would you trust that my algorithm doesn't have a backdoor in it? On the other hand,
this oughta be really good if you want to obfuscate the length of whatever it is you're encrypting but just
to be safe you might want to additionally encrypt it with a verified algorithm that is currently deemed
secure but again... why would you trust such an algorithm if you're paranoid? 