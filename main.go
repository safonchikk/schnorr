package main

import (
	"crypto/elliptic"
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
	R *big.Int
	s *big.Int
}

func GenKeys() (keys KeyPair) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	keys.private, _ = rand.Int(rand.Reader, &n) //private key
	t := elliptic_curves.ScalarMult(*keys.private, g)
	keys.public = t.X //public key
	if keys.public.Cmp(new(big.Int)) == 0 || !elliptic_curves.IsOnCurveCheck(t) {
		return GenKeys()
	}
	p := elliptic.P256().Params().P
	gx := elliptic.P256().Params().Gx
	gy := elliptic.P256().Params().Gy
	x, y := elliptic.P256().ScalarBaseMult(p.Bytes())
	if x.Cmp(gx) == 0 && y.Cmp(gy) == 0 {
		fmt.Println("success")
	}
	if elliptic_curves.IsEqual(elliptic_curves.ScalarMult(*p, g), g) {
		fmt.Println("aaa")
	}
	return keys
}

func SignMessage(m string, keys KeyPair) (signature Signature) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	r, _ := rand.Int(rand.Reader, &n)                            //private key
	signature.R = elliptic_curves.ScalarMult(*keys.private, g).X //public key
	str := append(signature.R.Bytes(), keys.public.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	e := new(big.Int).SetBytes(hash[:])
	signature.s = new(big.Int)
	var t big.Int
	signature.s.Add(r, t.Mul(keys.private, e))
	return signature
}

func Verify(signature Signature, m string, P *big.Int) (res bool) {
	g := elliptic_curves.BasePointGGet()
	str := append(signature.R.Bytes(), P.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	e := new(big.Int).SetBytes(hash[:])
	sum := new(big.Int)
	sG := elliptic_curves.ScalarMult(*signature.s, g).X
	var t big.Int
	sum.Add(sG, t.Mul(P, e))
	fmt.Println(sum)
	fmt.Println(signature.R)
	return sum.Cmp(signature.R) == 0
}

func main() {
	m := "Hello, I am totally the person who signed this"
	keys := GenKeys()
	signature := SignMessage(m, keys)
	res := Verify(signature, m, keys.public)
	fmt.Println(res)
}
