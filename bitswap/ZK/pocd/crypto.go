package pocd

import (
	"fmt"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"math/big"
	"os"
)

const P = "0x2523648240000001BA344D80000000086121000000000013A700000000000013"

func CryptoPBKDF2(seed *big.Int) []*big.Int {
	ret := make([]*big.Int, NumVar)
	for i := 0; i < NumVar; i++ {
		iBig := new(big.Int).SetInt64(int64(i))
		u, _ := poseidon.Hash([]*big.Int{seed, iBig})
		sum := u
		for j := 0; j < NumIter; j++ {
			u, _ = poseidon.Hash([]*big.Int{seed, u})
			sum = sum.Add(sum, u)
		}
		ret[i] = sum
	}
	return ret
}

func Encrypt(rawData []*big.Int, seed *big.Int) []*big.Int {
	key := CryptoPBKDF2(seed)
	ret := make([]*big.Int, NumVar)
	for i := 0; i < NumVar; i++ {
		ret[i] = rawData[i].Add(rawData[i], key[i])
	}
	return ret
}

func BytesToBigInts(input []byte, size int) []*big.Int {
	var bigInts []*big.Int

	for i := 0; i < len(input); i += size {
		end := i + size
		if end > len(input) {
			end = len(input)
		}

		bigInt := new(big.Int).SetBytes(input[i:end])
		bigInts = append(bigInts, bigInt)
	}
	fmt.Println("bigInts length: ", len(bigInts))
	if len(bigInts) == NumVar {
		return bigInts
	} else if len(bigInts) > NumVar {
		//print error message
		fmt.Print("Error: too many bigInts")
		os.Exit(1)
		return bigInts
	} else {
		for i := len(bigInts); i < NumVar; i++ {
			bigInts = append(bigInts, big.NewInt(0))
		}
		return bigInts
	}

}

func BigIntsToBytes(input []*big.Int, size int) []byte {
	var bytes []byte

	for _, bigInt := range input {
		for i := 0; i < size-len(bigInt.Bytes()); i++ {
			bytes = append(bytes, 0)
		}
		bytes = append(bytes, bigInt.Bytes()...)
	}

	return bytes
}

func EncryptToBig(rawData []byte, seed *big.Int) []*big.Int {
	data := BytesToBigInts(rawData, 31)
	key := CryptoPBKDF2(seed)
	for i := 0; i < NumVar; i++ {
		data[i].Add(data[i], key[i])
	}
	return data
}

func Decrypt(data []byte, seed *big.Int) []byte {
	p, _ := new(big.Int).SetString(P, 0)
	key := CryptoPBKDF2(seed)
	dataBig := BytesToBigInts(data, 33)
	for i := 0; i < NumVar; i++ {
		if dataBig[i].Cmp(key[i]) < 0 {
			dataBig[i].Add(dataBig[i], p)
		}
		dataBig[i].Sub(dataBig[i], key[i])
	}
	return BigIntsToBytes(dataBig, 31)
}
