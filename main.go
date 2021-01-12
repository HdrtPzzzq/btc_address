package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// Get []byte of hexa string input

func getInput() []byte {

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

	return inputSlice

}

func sumRipemd160(hashKey []byte) []byte { // Ripemd160 hash

	hasher := ripemd160.New()
	hasher.Write([]byte(hashKey))
	hashBytes := hasher.Sum(nil)

	return hashBytes

}

func sumHmac(data []byte, key []byte) []byte { // Hmac using sha512 hash

	hash := hmac.New(sha512.New, key)
	hash.Write(data)
	hashBytes := hash.Sum(nil)

	return hashBytes

}

// Transform a private key ([]bytes) into its public key ([]byte)

func privToPub(privKey []byte, compressed bool) []byte {

	_, pubKey := secp256k1.PrivKeyFromBytes(privKey)
	ecdsaPubKey := pubKey.ToECDSA()

	pubKeyByte := append(ecdsaPubKey.X.Bytes(), ecdsaPubKey.Y.Bytes()...)
	pubKeyByte = append([]byte{4}, pubKeyByte...)

	if compressed && ecdsaPubKey.Y.Bit(0) == 0 {
		pubKeyByte = append([]byte{2}, ecdsaPubKey.X.Bytes()...)
	} else if compressed {
		pubKeyByte = append([]byte{3}, ecdsaPubKey.X.Bytes()...)
	}

	return pubKeyByte

}

// Transform a private key to a Btc address

func keyToBtc() string {

	privKey := getInput()

	pub := privToPub(privKey, true)

	hashKey1 := sha256.Sum256(pub)

	hashKey2 := append([]byte{0}, sumRipemd160(hashKey1[:])...)

	hashKey3 := sha256.Sum256(hashKey2[:])

	hashKey4 := sha256.Sum256(hashKey3[:])

	checksum := hashKey4[:4]

	hash := append(hashKey2, checksum...)

	address := base58.Encode(hash)

	return address

}

// Generate the seed of mnemonic phrase from a number of bits

func generateSeed(size int) []byte {

	bitsNumber := size / 8
	checkSum := size / 32
	randomBytes := make([]byte, bitsNumber)
	_, err := rand.Read(randomBytes)

	if err != nil {
		fmt.Println("Error:", err)
		panic(err)
	}

	bitString := ""

	for i := 0; i < bitsNumber; i++ {

		b := fmt.Sprintf("%b", randomBytes[i])

		for len(b) < 8 {
			b = "0" + b
		}

		bitString += b

	}

	firstSha256Byte := sha256.Sum256(randomBytes)[0]

	bitString += fmt.Sprintf("%08b", firstSha256Byte)
	wordIndex := make([]int, (size+checkSum)/11)

	for i := 0; i < (size + checkSum); i += 11 {

		index, _ := strconv.ParseInt(bitString[i:i+11], 2, 64)
		wordIndex[i/11] = int(index)

	}

	wordByte, _ := ioutil.ReadFile("english")
	wordList := strings.Split(string(wordByte), "\n")

	words := wordList[wordIndex[0]]

	for i := 1; i < (size+checkSum)/11; i++ {

		index := wordIndex[i]

		words += " "
		words += wordList[index]

	}

	seed := pbkdf2.Key([]byte(words), []byte("mnemonic"), 2048, 64, sha512.New)

	return seed

}

// Generate the master private key from the seed

func masterPrivKey(seed []byte) []byte {

	extendedPrivateKey := sumHmac(seed, []byte("Bitcoin seed"))
	return extendedPrivateKey

}

func extendedPrivKey(extendedPrivKey []byte, index uint32) []byte {

	// Int modulo
	n, _ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337", 10)

	// Index in byte's slice
	indexByte := make([]byte, 4)
	binary.BigEndian.PutUint32(indexByte, index)

	// Hash with private key and chaincode
	data := append(extendedPrivKey[:32], indexByte...)
	key := extendedPrivKey[32:]
	hash := sumHmac(data, key)

	// Transform byte's slice hash and private key into hexa string
	hashString := hex.EncodeToString(hash)
	privKeyString := hex.EncodeToString(extendedPrivKey[:32])

	// Make Int with previous strings
	hashInt, _ := new(big.Int).SetString(hashString, 16)
	privKeyInt, _ := new(big.Int).SetString(privKeyString, 16)

	// Compute the private key's child with Int
	childPrivKeyInt := big.NewInt(0)
	childPrivKeyInt.Add(privKeyInt, hashInt)
	childPrivKeyInt.Mod(childPrivKeyInt, n)

	// Make it string
	childPrivKeyString := fmt.Sprintf("%x", childPrivKeyInt)

	// Make it byte's slice
	childPrivKey, _ := hex.DecodeString(childPrivKeyString)

	return childPrivKey

}

func extendedPubKey(extendedPrivKey []byte) []byte {

	privKey := extendedPrivKey[:32]
	chainCode := extendedPrivKey[32:]

	pubKey := privToPub(privKey, true)

	extendedPubKey := append(pubKey, chainCode...)

	return extendedPubKey

}

func main() {

}
