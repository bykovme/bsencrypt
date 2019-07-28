package bsencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// AES256 consts
const cryptIDAES256 = "8GA63DMN"
const aes256 = "AES256"
const constAESkeyLength = 32 // AES-256
const constSaltString = "DJVJOT2K1RSVTBQqnxijkiwIz0LhGvUO"

type cipherAES256 struct {
	generatedKey []byte
	passwordKey  []byte
}

func (cipher256 *cipherAES256) CleanAndInit() {
	cipher256.generatedKey = nil
	cipher256.passwordKey = nil
}

func (cipher256 cipherAES256) GetGryptID() string {
	return cryptIDAES256
}

func (cipher256 cipherAES256) GetCipherName() string {
	return aes256
}
func (cipher256 *cipherAES256) SetPassword(password string) (err error) {

	cipher256.passwordKey = cipher256.makePasswordKey(password)
	err = cipher256.SetPasswordKey(cipher256.passwordKey)
	if err != nil {
		return err
	}
	return nil
}

func (cipher256 cipherAES256) makePasswordKey(password string) (keyDataOut []byte) {
	if len(password) < constAESkeyLength {
		password = password + constSaltString
	}
	return []byte(password)
}

func (cipher256 cipherAES256) GetPasswordKey() []byte {
	return cipher256.passwordKey
}

func (cipher256 *cipherAES256) SetPasswordKey(keyDataIn []byte) (err error) {
	if len(keyDataIn) < constAESkeyLength {
		return formError(BSENCRPT0002WrongKeyLength, aes256, "SetPasswordKey", "Key length must be  at least 32 bytes")
	}
	cipher256.passwordKey = keyDataIn
	salt := []byte(constSaltString)
	cipher256.generatedKey, err = scrypt.Key(keyDataIn, salt, 16384, 8, 1, constAESkeyLength)
	if err != nil {
		return err
	}
	return nil
}

func (cipher256 cipherAES256) IsKeyGenerated() bool {
	if cipher256.passwordKey == nil ||
		cipher256.generatedKey == nil ||
		len(cipher256.generatedKey) != constAESkeyLength {
		return false
	}
	return true
}

func (cipher256 *cipherAES256) Encrypt(text string) (string, error) {
	if cipher256.IsKeyGenerated() == false {
		return "", formError(BSENCRPT0001EncKeyIsNotSet, aes256, "Encrypt")
	}

	encryptedData, err := cipher256.EncryptBLOB(text)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(encryptedData), nil
}

func (cipher256 *cipherAES256) EncryptBLOB(text string) ([]byte, error) {
	if cipher256.IsKeyGenerated() == false {
		return nil, formError(BSENCRPT0001EncKeyIsNotSet, aes256, "EncryptBLOB")
	}
	plainData := []byte(text)
	encryptedData, err := cipher256.EncryptBIN(plainData)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

func (cipher256 *cipherAES256) EncryptBIN(inData []byte) (outData []byte, err error) {
	if cipher256.IsKeyGenerated() == false {
		return nil, formError(BSENCRPT0001EncKeyIsNotSet)
	}

	block, err := aes.NewCipher(cipher256.generatedKey)
	if err != nil {
		return nil, formError("aes.NewCipher", err.Error())
	}
	encryptedData := make([]byte, aes.BlockSize+len(inData))
	iv := encryptedData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, formError("ReadFull", err.Error())
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedData[aes.BlockSize:], inData)

	return encryptedData, nil
}

func (cipher256 *cipherAES256) Decrypt(cryptedText string) (string, error) {

	if cipher256.IsKeyGenerated() == false {
		return "", formError(BSENCRPT0001EncKeyIsNotSet, aes256, "Decrypt")
	}

	dataIn, err := base64.URLEncoding.DecodeString(cryptedText)

	if err != nil {
		return "", err
	}

	decryptedText, err := cipher256.DecryptBLOB(dataIn)
	if err != nil {
		return "", err
	}

	return decryptedText, nil
}

func (cipher256 *cipherAES256) DecryptBLOB(dataIn []byte) (string, error) {
	if cipher256.IsKeyGenerated() == false {
		return "", formError(BSENCRPT0001EncKeyIsNotSet, aes256, "DecryptBLOB")
	}

	dataOut, err := cipher256.DecryptBIN(dataIn)
	if err != nil {
		return "", err
	}
	return string(dataOut), nil
}

func (cipher256 *cipherAES256) DecryptBIN(dataIn []byte) (dataOut []byte, err error) {
	if cipher256.IsKeyGenerated() == false {
		return nil, formError(BSENCRPT0001EncKeyIsNotSet, aes256, "DecryptBIN")
	}

	block, err := aes.NewCipher(cipher256.generatedKey)

	if err != nil {
		return nil, err
	}

	if len(dataIn) < aes.BlockSize {
		return nil, errors.New("Cipher text is too short for AES")
	}

	iv := dataIn[:aes.BlockSize]
	dataWork := dataIn[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(dataWork, dataWork)

	return dataWork, nil
}
