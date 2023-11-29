package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/safonchikk/elliptic_curves"
	"math/big"
)

type KeyPair struct {
	private *big.Int
	public  *big.Int
}

type Signature struct {
	m string
	R *big.Int
	P *big.Int
	e *big.Int
}

func GenKeys() (keys KeyPair) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	keys.private, _ = rand.Int(rand.Reader, &n)                  //private key
	keys.public = elliptic_curves.ScalarMult(*keys.private, g).X //public key
	return keys
}

func GenNonce(k *big.Int) (nonceKeys KeyPair) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	nonceKeys.private, _ = rand.Int(rand.Reader, &n)       //private key
	nonceKeys.public = elliptic_curves.ScalarMult(*k, g).X //public key
	return nonceKeys
}

func SignMessage(m string, keys, nonceKeys KeyPair) (signature Signature) {
	str := append(nonceKeys.public.Bytes(), keys.public.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	signature.e = new(big.Int).SetBytes(hash[:])
	s := new(big.Int)
	s.Add(nonceKeys.private, keys.private.Mul(keys.private, signature.e))
	signature.m = m
	signature.P = keys.public
	signature.R = nonceKeys.public
	return signature
}

func main() {
	fmt.Println("")
}
