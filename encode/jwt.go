package encode

import (
	"errors"
	"fmt"
	"log"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type TestClaims struct {
	Text string `json:"text"`
	jwt.StandardClaims
}

func Encode(plaintext []byte, key []byte) ([]byte, error) {
	var claims TestClaims
	claims.Text = string(plaintext)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ciphertext, err := token.SignedString(key)
	if err != nil {
		fmt.Printf("Encode error: %v\n", err)
		return nil, err
	}
	return []byte(ciphertext), nil
}

func PrepareDecoding(auth string) (string, error) {
	auths := strings.Split(auth, " ")
	if len(auths) > 1 {
		return auths[1], nil
	}
	return "", errors.New("Invalid Auth Header")
}
func Decode(ciphertext []byte, key []byte) (string, error) {
	var result string
	token, err := jwt.ParseWithClaims(string(ciphertext), &TestClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		log.Println(err.Error())
	}
	if claims, ok := token.Claims.(*TestClaims); ok && token.Valid {

		result = claims.Text
		return result, err
	}
	fmt.Println("decrypted : failed")
	return result, err
}
