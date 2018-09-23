package MRomanCipher

import (
	"bytes"
	"crypto/rand"
)

type Cipher struct {
	dkey []byte
	prng *PRNG
}

// The MRomanCipher is a cipher with the following properties:
//  - Ciphertexts of the same plaintext always have a different length.
//    This makes it hard to correlate ciphertexts with plaintexts based on lengths.
//  - Ciphertexts contain random bytes at random locations.
//    This makes it hard to correlate locations of bytes in the plaintext with
//    locations of bytes in the ciphertext.
//  - Ciphertexts of the same plaintext always look different. This is achieved
//    through an IV. This makes it hard to tell whether two ciphertexts contain
//    the same plaintext. The IV is additionally encrypted. 
//
// The key is internally hashed such that the key length is always
// 512 bits. 
func NewCipher(key []byte, hashf HashFunction) *Cipher {
	prng := NewPRNG(key, hashf)

	// Create a "derived" key. We don't want that in case
	// some weaknesses are found that one can retrieve the key
	// used in plaintext. That's why we only use it hashed. 
	dkey := make([]byte, size)
	copy(dkey, prng.hash(key))
	
	for i := 0; i < size; i++ {
		dkey[i] += byte(i)
		dkey[i] ^= prng.Next()
	}
	
	dkey = prng.hash(dkey)
	
	return &Cipher {
		dkey: dkey,
		prng: prng,
	}
}

// Ecrypt data. Please be aware that worst case there are
// 3 bytes inserted at every location. Encrypt internally
// performs 3 rounds. This means that the ciphertext could
// be up to 12 times as large + 48 bytes for IV. This does
// not encrypt in place so make sure you have enough memory
// available.
func (c *Cipher) Encrypt(data []byte) []byte {
	for i := 0; i < 3; i++ {
		data = c.encrypt(data)
	}
	
	return data
}

// Decrypt data. This does not decrypt in place so make sure you
// have enough memory available. 
func (c *Cipher) Decrypt(data []byte) []byte {
	for i := 0; i < 3; i++ {
		data = c.decrypt(data)
	}
	
	return data
}

func (c *Cipher) decrypt(data_ []byte) []byte {
	data := make([]byte, len(data_))
	copy(data, data_)
	
	// ** Reverse encryption stage **
	c.prng.Reset()
	
	for i := 0; i < len(data); i++ {
		data[i] ^= c.dkey[i >> 2]
		
		v := c.prng.Next() & 0x03
		switch v {
		case 0x00:
			data[i] = (data[i] << 1) | (data[i] >> 7)
		case 0x01:
			data[i] = (data[i] >> 1) | (data[i] << 7)
		case 0x02:
			data[i] = ^data[i]
		case 0x03:
			bl := data[i] & 0x0F
			bh := data[i] >> 4
			data[i] = (bl << 4) | bh
		}
	}
	
	c.prng.Reset()
	
	for r := 0; r < 3; r++ {
		for i := 0; i < len(data); i++ {
			data[i] ^= c.dkey[c.prng.Next() >> 2] ^ c.prng.Next()
		}
		
		n := int(c.prng.Next())
		
		// throw away some values.
		for i := 0; i < n; i++ {
			c.prng.Next()
		}
	}
	
	// Reset and allocation
	c.prng.Reset()
	buf := bytes.NewBuffer(nil)
	iv := make([]byte, 16)
	
	// Read iv
	copy(iv, data[0:16])
	data = data[16:]
	
	
	// ** Reverse ciphertext stretching stage **
	for i := 0; i < len(data); i++ {
	
		// Skip the random bytes.
		rnd := c.prng.Next()
		rnd ^= iv[rnd >> 4]
		
		if (rnd & 0x03) == 0x00 {
			rnd = c.prng.Next()
			rnd ^= iv[rnd >> 4]
			rndBytes := rnd & 0x03
			
			for j := byte(0); j < rndBytes; j++ {
				c.prng.Next()
				i++
			}
		}
		 
		b := data[i] ^ c.prng.Next() ^ iv[c.prng.Next() >> 4]
		buf.WriteByte(b)
	}
	
	return buf.Bytes()
}

func (c *Cipher) encrypt(data []byte) []byte {
	// Reset and allocation.
	c.prng.Reset()
	buf := bytes.NewBuffer(nil)
	iv := make([]byte, 16)
	
	// Generate a cryptograhically strong IV. 
	rand.Read(iv)
	buf.Write(iv)
	
	// ** Ciphertext stretching stage **
	for i := 0; i < len(data); i++ {
	
		// At random locations insert a random number of
		// random bytes. This ensures that the ciphertext will have a
		// random length. Through the use of IV even if the plaintext is
		// the same the ciphertext will always have a different length. 
		// This makes it harder to correlate positions in the plaintext with
		// the ciphertext as well as making it harder to correlate plaintexts
		// with ciphertexts based on length. 
		rnd := c.prng.Next()
		rnd ^= iv[rnd >> 4]
		
		if (rnd & 0x03) == 0x00 {
			rnd = c.prng.Next()
			rnd ^= iv[rnd >> 4]
			rndBytes := rnd & 0x03
			
			for j := byte(0); j < rndBytes; j++ {
				buf.WriteByte(c.prng.Next())
			}
		}
		
		// XOR each byte with a random byte from the PRNG and a
		// random byte from the IV. This is to ensure that the ciphertexts
		// of the same plaintext always look different. 
		b := data[i] ^ c.prng.Next() ^ iv[c.prng.Next() >> 4]
		buf.WriteByte(b)
	}
	
	// ** Encryption stage **
	data = buf.Bytes()
	
	// We don't want the IV to be visible in plaintext. Thus, we
	// also encrypt the IV. 
	
	c.prng.Reset()
	
	for r := 0; r < 3; r++ {
		for i := 0; i < len(data); i++ {
			data[i] ^= c.dkey[c.prng.Next() >> 2] ^ c.prng.Next()
		}
		
		n := int(c.prng.Next())
		
		// throw away some values.
		for i := 0; i < n; i++ {
			c.prng.Next()
		}
	}
	
	c.prng.Reset()
	
	for i := 0; i < len(data); i++ {
		v := c.prng.Next() & 0x03
		switch v {
		case 0x00:
			data[i] = (data[i] >> 1) | (data[i] << 7)
		case 0x01:
			data[i] = (data[i] << 1) | (data[i] >> 7)
		case 0x02:
			data[i] = ^data[i]
		case 0x03:
			bl := data[i] & 0x0F
			bh := data[i] >> 4
			data[i] = (bl << 4) | bh
		}
		
		data[i] ^= c.dkey[i >> 2]
	}
	
	return data
}