package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error)
	}

	srcFile, err := os.Open(source)
	handleError(err)

	defer srcFile.Close()

	plaintext, err := io.ReadAll(srcFile)
	handleError(err)

	key := password

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	handleError(err)

	aesgcm, err := cipher.NewGCM(block)
	handleError(err)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)

	dstFile, err := os.Create(source)
	handleError(err)
	defer dstFile.Close()

	_, err = dstFile.Write(ciphertext)
	handleError(err)
}

func Decrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsExist(err) {
		panic(err.Error())
	}

	srcFile, err := os.Open(source)
	handleError(err)

	defer srcFile.Close()

	ciphertext, err := io.ReadAll(srcFile)
	handleError(err)

	key := password
	salt := ciphertext[len(ciphertext)-12:]
	str := hex.EncodeToString(salt)
	nonce, err := hex.DecodeString(str)
	handleError(err)

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	handleError(err)

	aesgcm, err := cipher.NewGCM(block)
	handleError(err)

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	handleError(err)

	dstFile, err := os.Create(source)
	handleError(err)
	defer dstFile.Close()

	_, err = dstFile.Write(plaintext)
	handleError(err)
}

func handleError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
