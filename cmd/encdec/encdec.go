package main

import (
	mrc "github.com/FMNSSun/mroman-cipher"
	"golang.org/x/crypto/sha3"
	"fmt"
)

func main() {
	c := mrc.NewCipher([]byte("hi there"), sha3.Sum512)
	
	data := []byte("hello, world!")
	encData := c.Encrypt(data)
	decData := c.Decrypt(encData)
	
	fmt.Printf("data:    %X\n", data)
	fmt.Printf("encData: %X\n", encData)
	fmt.Printf("decData: %X\n", decData)
}