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

# How secure is this?

Decently secure. Decently secure is not a scientific term.

# Who uses this?

I use this to encrypt my passwords and other stuff I want to keep secret. 

## So you're confident that this is secure?

Yes, pretty much. But by all means I'm an amateur and I'm not encouraging anyone to use this. This is only
on github due to: security through obscuritiy. I strongly believe that this algorithm is secure but it's bloated
and inefficient as fuck. 

## Can you give me a rough description of how it works?

It roughly works like this. We generate a random IV and seed a PRNG using the encryption key. We'll
insert a random number of random bytes at random locations in the plaintext as well as encrypting each byte
with bytes from the IV and the PRNG. Then the IV and the output of this first stage are concatenated. This
I refer to the "ciphertext stretching" stage as it's only purpose is to obfuscate the length of the plaintext
and the positions of "actual data" bytes. Then everything is XORed with bytes from the PRNG and then there's
some random left/right rotations and nibble swaps and binary complement in there. Then there's the 
"substitution" stage which substitutes nibbles with nibbles looked up in an s-box. There are 8 different
s-boxes and for every nibble one of those is selected at random (using a PRNG). Then there's a last stage
that ensures that there's a dependency on bytes we've encrypted so far. 

# I found a weakness (or a bug)

Just let me know through an issue. If you find a weakness that seriously breaks the algorithm itself then
or you think you can find one let me know and we might even arrange some private bounty agreement such that
you don't waste time for nothing in return. 