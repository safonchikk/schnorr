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
	public  elliptic_curves.ECPoint
}

type Signature struct {
	R elliptic_curves.ECPoint
	s *big.Int
}

func GenKeys() (keys KeyPair) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	keys.private, _ = rand.Int(rand.Reader, &n)
	keys.public = elliptic_curves.ScalarMult(*keys.private, g)
	if keys.public.X.Cmp(new(big.Int)) == 0 || !elliptic_curves.IsOnCurveCheck(keys.public) {
		return GenKeys()
	}
	return keys
}

func SignMessage(m string, keys KeyPair) (signature Signature) {
	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()
	r, _ := rand.Int(rand.Reader, &n)               //private key
	signature.R = elliptic_curves.ScalarMult(*r, g) //public key
	str := append(signature.R.X.Bytes(), keys.public.X.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	e := new(big.Int).SetBytes(hash[:])
	signature.s = new(big.Int)
	var t big.Int
	signature.s.Add(r, t.Mul(keys.private, e))
	signature.s.Mod(signature.s, &n)
	return signature
}

func MultiSignMessage(m string, keys []KeyPair) (signature Signature, X elliptic_curves.ECPoint) {
	var xConc []byte
	for i := range keys {
		xConc = append(xConc, keys[i].public.X.Bytes()...)
	}
	hashl := sha256.Sum256(xConc)
	a := make([]big.Int, len(keys))
	for i := range a {
		l := new(big.Int).SetBytes(hashl[:])
		hash := sha256.Sum256(append(l.Bytes(), keys[i].public.X.Bytes()...))
		a[i].SetBytes(hash[:])
	}
	X = elliptic_curves.ScalarMult(a[0], keys[0].public)
	for i := 1; i < len(keys); i++ {
		X = elliptic_curves.AddECPoints(X, elliptic_curves.ScalarMult(a[i], keys[i].public))
	}

	g := elliptic_curves.BasePointGGet()
	n := elliptic_curves.BasePointOrder()

	r := make([]*big.Int, len(keys))
	R := make([]elliptic_curves.ECPoint, len(keys))
	for i := range R {
		r[i], _ = rand.Int(rand.Reader, &n)
		R[i] = elliptic_curves.ScalarMult(*r[i], g)
	}
	signature.R = R[0]
	for i := 1; i < len(keys); i++ {
		signature.R = elliptic_curves.AddECPoints(signature.R, R[i])
	}

	str := append(signature.R.X.Bytes(), X.X.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	e := new(big.Int).SetBytes(hash[:])

	signature.s = new(big.Int)
	var t big.Int
	for i := range keys {
		signature.s.Add(signature.s, t.Mul(t.Mul(keys[i].private, e), &a[i]))
		signature.s.Add(signature.s, r[i])
		signature.s.Mod(signature.s, &n)
	}
	return signature, X
}

func Verify(signature Signature, m string, P elliptic_curves.ECPoint) (res bool) {
	g := elliptic_curves.BasePointGGet()
	str := append(signature.R.X.Bytes(), P.X.Bytes()...)
	str = append(str, []byte(m)...)
	hash := sha256.Sum256(str)
	e := new(big.Int).SetBytes(hash[:])
	sG := elliptic_curves.ScalarMult(*signature.s, g)
	t := elliptic_curves.AddECPoints(signature.R, elliptic_curves.ScalarMult(*e, P))
	return elliptic_curves.IsEqual(sG, t)
}

func main() {
	m := "Hello, I am totally the person who signed this"
	keys := GenKeys()
	signature := SignMessage(m, keys)
	res := Verify(signature, m, keys.public)
	fmt.Println(res)
	muSigKeys := make([]KeyPair, 5)
	for i := range muSigKeys {
		muSigKeys[i] = GenKeys()
	}
	muSig, X := MultiSignMessage(m, muSigKeys)
	res = Verify(muSig, m, X)
	fmt.Println(res)
}
