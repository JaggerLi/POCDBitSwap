package pocd

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/liyue201/gnark-circomlib/circuits"
)

type EncryptSampleCircuit struct {
	RawData    []frontend.Variable
	EncData    []frontend.Variable `gnark:",public"`
	Seed       frontend.Variable
	Position   frontend.Variable `gnark:",public"`
	SeedCommit frontend.Variable `gnark:",public"`
	DataCommit frontend.Variable `gnark:",public"`
}

func (circuit *EncryptSampleCircuit) Define(api frontend.API) error {
	size := len(circuit.RawData) //will be fixed value for each circuit
	key := PBKDF2_Position(api, circuit.Seed, circuit.Position, size)

	for i := 0; i < size; i++ {
		api.AssertIsEqual(circuit.EncData[i], api.Add(circuit.RawData[i], key[i]))
	}

	api.AssertIsEqual(circuit.SeedCommit, circuits.Poseidon(api, []frontend.Variable{circuit.Seed}))
	hash, _ := mimc.NewMiMC(api)
	hash.Write(circuit.RawData[:]...)
	api.AssertIsEqual(circuit.DataCommit, hash.Sum())
	return nil
}

func PBKDF2_Position(api frontend.API, seed frontend.Variable, position frontend.Variable, size int) []frontend.Variable {

	ret := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		u := circuits.Poseidon(api, []frontend.Variable{seed, api.Add(position, i)})
		sum := u
		for j := 0; j < NumIter; j++ {
			u = circuits.Poseidon(api, []frontend.Variable{seed, u})
			sum = api.Add(sum, u)
		}
		ret[i] = sum
	}
	return ret
}
