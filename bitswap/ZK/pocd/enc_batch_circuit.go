package pocd

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/liyue201/gnark-circomlib/circuits"
)

const (
	BatchNum = 10
)

type SeedBatchCircuit struct {
	Seed       [BatchNum]frontend.Variable
	TemKeys    [BatchNum]frontend.Variable
	SeedCommit [BatchNum]frontend.Variable       `gnark:",public"`
	SeedEnc    [BatchNum][2]twistededwards.Point `gnark:",public"`
	PubKeys    [BatchNum]eddsa.PublicKey         `gnark:",public"`
}

func (circuit *SeedBatchCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		panic(err)
	}
	for i := 0; i < BatchNum; i++ {
		api.AssertIsEqual(circuit.SeedCommit[i], circuits.Poseidon(api, []frontend.Variable{circuit.Seed[i]}))
		// TODO: ElGamal
		c1, c2 := ElgamalEncrypt(api, curve, circuit.TemKeys[i], circuit.PubKeys[i], circuit.Seed[i])
		api.AssertIsEqual(c1.X, circuit.SeedEnc[i][0].X)
		api.AssertIsEqual(c1.Y, circuit.SeedEnc[i][0].Y)
		api.AssertIsEqual(c2.X, circuit.SeedEnc[i][1].X)
		api.AssertIsEqual(c2.Y, circuit.SeedEnc[i][1].Y)
	}

	return nil
}

func ElgamalEncrypt(api frontend.API, curve twistededwards.Curve, r frontend.Variable, pubkey eddsa.PublicKey, msg frontend.Variable) (twistededwards.Point, twistededwards.Point) {
	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	// project the message on to the curve
	M := curve.ScalarMul(base, msg)
	curve.AssertIsOnCurve(M)

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := curve.ScalarMul(base, r) // K = r * Base - Public key

	S := curve.ScalarMul(pubkey.A, r) // S = r*A
	curve.AssertIsOnCurve(S)

	Cipher := curve.Add(S, M) // C = S + M

	return K, Cipher

}
