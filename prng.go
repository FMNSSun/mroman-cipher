package MRomanCipher

const size = 64

type HashFunction func([]byte) [size]byte

type PRNG struct {
	seed  []byte
	q     []byte
	block []byte
	hashf  HashFunction
	ix    int
	
	x uint64
	y uint64
	shift uint64
	jx uint64
}

func (prng *PRNG) hash(data []byte) []byte {
	h := prng.hashf(data)
	return h[:]
}

var NullHashF HashFunction = func(data []byte) [64]byte {
	var h [64]byte
	return h
}

// Creates a new PRNG based on a hash function. The hash function
// must return a hash of exactly 64 bytes. You should choose a 
// secure hash function.
func NewPRNG(key []byte, hashf HashFunction) *PRNG {
	prng := &PRNG{
		hashf: hashf,
	}

	prng.seed = prng.hash(key)

	prng.Reset()

	return prng
}

func (prng *PRNG) Reset() {
	prng.q = make([]byte, size*2)

	copy(prng.q, prng.seed)
	copy(prng.q[size:], prng.hash(prng.seed))

	prng.block = prng.hash(prng.q)
	prng.ix = 0
	
	var x uint64 = 0x4782394ABCBCDE11
	
	for i := 0; i < size / 8; i++ {
		j := i * 8
		
		b0 := uint64(prng.seed[j + 0])
		b1 := uint64(prng.seed[j + 1])
		b2 := uint64(prng.seed[j + 2])
		b3 := uint64(prng.seed[j + 3])
		b4 := uint64(prng.seed[j + 4])
		b5 := uint64(prng.seed[j + 5])
		b6 := uint64(prng.seed[j + 6])
		b7 := uint64(prng.seed[j + 7])
		
		x ^= (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) | (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
	}
	
	prng.x = ^x
	prng.y = x ^ 0xBA7878B9133CCC99
	prng.shift = 0
	prng.jx = 0
}

func (prng *PRNG) Next2() byte {
	prng.x = ^prng.y
	next := byte((prng.x >> prng.shift) & 0xFF)
	prng.y = ^((prng.y >> 4) ^ (prng.y << 4) ^ prng.x) | (uint64(1) << prng.shift)
	prng.y = ((prng.y >> 1) | (prng.y << 63)) ^ ((prng.jx << prng.shift) | (prng.jx >> (64 - prng.shift)))
	
	prng.jx++
	prng.shift++
	if prng.shift > 56 {
		prng.shift = 0
	}
	
	return next
}

func (prng *PRNG) Next() byte {

	next := prng.Next2()
	
	if prng.ix < size {
		val := prng.block[prng.ix]
		prng.ix++
		return val ^ next
	} else {
		copy(prng.q[size:], prng.block)
		prng.block = prng.hash(prng.q)
		prng.ix = 1
		return prng.block[0] ^ next
	}
}
