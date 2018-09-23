package main

import (
	mrc "github.com/FMNSSun/mroman-cipher"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
)

func main() {
	seed := flag.String("seed", "hi there", "Seed");
	
	hashf := sha3.Sum512
	
	prng := mrc.NewPRNG([]byte(*seed), hashf)
	
	hist := make([]uint32, 256)
	
	for i := uint64(0); i < 10*1024*1024; i++ {
		hist[prng.Next2()]++
	}
	
	max := uint32(0);
	
	for i := 0; i < 256; i++ {
		if hist[i] > max {
			max = hist[i]
		}
	}
	
	fmax := float64(max)
	
	for i := 0; i < 256; i++ {
		hval := float64(hist[i]);
		fmt.Printf("%03d := %.4f\n", i, hval / fmax);
	}
}