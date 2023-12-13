package pocd

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/liyue201/gnark-circomlib/circuits"
	"math/big"
	"os"
	"path"
)

const (
	MaxDataSize = 100000 // Byte
	NumVar      = (MaxDataSize*8 + 252) / 253
	NumIter     = 10
)

type EncryptCircuit struct {
	RawData [NumVar]frontend.Variable
	EncData [NumVar]frontend.Variable
	Seed    frontend.Variable
}

type Info struct {
	Seed    *big.Int
	RawData []*big.Int
	EncData []*big.Int
}

func (circuit *EncryptCircuit) Define(api frontend.API) error {
	key := PBKDF2(api, circuit.Seed)
	for i := 0; i < NumVar; i++ {
		api.AssertIsEqual(circuit.EncData[i], api.Add(circuit.RawData[i], key[i]))
	}
	return nil
}

// Using a fixed Salt=0 because we only need this key once
// The generated key length is equal to NumVar
// K_i = F(Seed, Salt, c, i) = \sum_i U_i
// U_i = H(Seed, U_{i-1})
// U_0 = H(Seed, i)
func PBKDF2(api frontend.API, seed frontend.Variable) []frontend.Variable {
	ret := make([]frontend.Variable, NumVar)
	for i := 0; i < NumVar; i++ {
		u := circuits.Poseidon(api, []frontend.Variable{seed, i})
		sum := u
		for j := 0; j < NumIter; j++ {
			u = circuits.Poseidon(api, []frontend.Variable{seed, u})
			sum = api.Add(sum, u)
		}
		ret[i] = sum
	}
	return ret
}

func GnerateProof(data Info) (groth16.Proof, witness.Witness) {
	pk := groth16.NewProvingKey(ecc.BN254)
	fmt.Println("loading pk...")
	Path := "../../bitswap/ZK/pocd"

	fpk, err2 := os.Open(path.Join(Path, "pocd.pk"))
	if err2 != nil {
		panic(err2)
	}

	buf := &bytes.Buffer{}
	buf.ReadFrom(fpk)
	_, err3 := pk.ReadFrom(buf)
	if err3 != nil {
		panic(err3)
	}
	fpk.Close()
	fmt.Println("loading pk done...")

	r1cs_ := groth16.NewCS(ecc.BN254)
	fmt.Println("loading r1cs...")

	f, _ := os.Open(path.Join(Path, "pocd.r1cs"))
	_, err1 := r1cs_.ReadFrom(f)
	if err1 != nil {
		panic(err1)
	}
	f.Close()
	fmt.Println("loading r1cs done...")

	var assignment EncryptCircuit
	assignment.Seed = data.Seed
	for i := 0; i < NumVar; i++ {
		assignment.RawData[i] = data.RawData[i]
		assignment.EncData[i] = data.EncData[i]
	}
	witness_, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness_.Public()
	proof, _ := groth16.Prove(r1cs_, pk, witness_)
	return proof, publicWitness
}

func VerifyProof(proof groth16.Proof, publicWitness witness.Witness) error {
	Path := "../../bitswap/ZK/pocd"

	vk := groth16.NewVerifyingKey(ecc.BN254)
	fmt.Println("loading vk...")

	fvk, _ := os.Open(path.Join(Path, "pocd.vk"))
	buf := &bytes.Buffer{}
	buf.ReadFrom(fvk)
	_, err3 := vk.ReadFrom(buf)
	if err3 != nil {
		panic(err3)
	}
	fvk.Close()
	fmt.Println("loading vk done...")

	return groth16.Verify(proof, vk, publicWitness)
}
