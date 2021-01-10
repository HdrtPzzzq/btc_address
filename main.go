package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func getInput() *secp256k1.PublicKey {

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')

	if err != nil {
		fmt.Println(err, "Can't read the input for some reasons")
		panic(err)
	}

	input = strings.TrimSpace(input)
	inputSlice, err := hex.DecodeString(input)

	if err != nil {
		fmt.Println(err, "Unable to decode string into byte's slice")
		panic(err)
	}

	_, pubKey := secp256k1.PrivKeyFromBytes(inputSlice)

	return pubKey
}

func printEcdsaKey(key *ecdsa.PublicKey) {

	x := fmt.Sprintf("0x%x", key.X)
	y := fmt.Sprintf("0x%x", key.Y)
	fmt.Println("The x coordinates of the key are:\n", x)
	fmt.Println("The y coordinates of the key are:\n", y)

}

func sumRipemd160(hashKey []byte) []byte {

	hasher := ripemd160.New()
	hasher.Write([]byte(hashKey))
	hashBytes := hasher.Sum(nil)

	return hashBytes

}

func btcAddress(ecdsaPubKey *ecdsa.PublicKey, compressed bool) string {

	pub := append(ecdsaPubKey.X.Bytes(), ecdsaPubKey.Y.Bytes()...)
	pub = append([]byte{4}, pub...)

	if ecdsaPubKey.Y.Bit(0) == 0 {
		pub = append([]byte{2}, ecdsaPubKey.X.Bytes()...)
	} else {
		pub = append([]byte{3}, ecdsaPubKey.X.Bytes()...)
	}

	hashKey1 := sha256.Sum256(pub)

	hashKey2 := append([]byte{0}, sumRipemd160(hashKey1[:])...)

	hashKey3 := sha256.Sum256(hashKey2[:])

	hashKey4 := sha256.Sum256(hashKey3[:])

	checksum := hashKey4[:4]

	hash := append(hashKey2, checksum...)

	address := base58.Encode(hash)

	return address

}

func main() {

	pubKey := getInput()
	ecdsaPubKey := pubKey.ToECDSA()

	address := btc_address(ecdsaPubKey, true)

	fmt.Println("This is your btc address:\n", address)

}
