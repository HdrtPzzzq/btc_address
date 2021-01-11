package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/pbkdf2"
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

func keyToBtc(ecdsaPubKey *ecdsa.PublicKey, compressed bool) string {

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

func generateSeed(size int) string {

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

	seedString := hex.EncodeToString(seed)

	return seedString

}

func main() {

	//pubKey := getInput()
	//ecdsaPubKey := pubKey.ToECDSA()

	//	address := keyToBtc(ecdsaPubKey, true)

	seed := generateSeed(128)

	fmt.Println("This is your seed\n" + seed)

}
