package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"training.happioteam.com/testencryption/encode"
	"training.happioteam.com/testencryption/encryption"
)

var tokenKey string
var key16 string
var port string

func init() {
	port = "7561"
	tokenKey = "2HD$ICMEKDOFIGJR%CJDIEISDCUENGQ3"
	key16 = "THE$!*JFUCAOSLFA"
}
func main() {
	startServer()
}
func startServer() {
	router := mux.NewRouter()
	router.HandleFunc("/testEncryption", TestEncrypt).Methods("POST")
	router.HandleFunc("/getToken", GetToken).Methods("POST")
	router.HandleFunc("/sendToken", ReadToken).Methods("POST")
	log.Printf("dev start at port %s!", port)
	log.Fatal(http.ListenAndServe(":"+string(port), router))

}

type Token struct {
	Token string `json:"token"`
}
type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func TestEncrypt(w http.ResponseWriter, r *http.Request) {
	var user UserInfo
	user.Username = "0945943534534"
	user.Password = "gkdmgmdfkhmfgmhgfhd"
	dataStr, err := json.Marshal(user)
	if err != nil {
		log.Println(err.Error())
		return
	}
	fmt.Println(string(dataStr))
	enText, err := encryption.Encrypt([]byte(dataStr), []byte(key16))
	if err != nil {
		log.Println(err.Error())
		return
	}
	fmt.Println(string(enText))
	deText, err := encryption.Decrypt([]byte(enText), []byte(key16))
	if err != nil {
		log.Println(err.Error())
		return
	}
	fmt.Println(string(deText))
}
func GetToken(w http.ResponseWriter, r *http.Request) {
	var user UserInfo
	user.Username = "0945943534534"
	user.Password = "gkdmgmdfkhmfgmhgfhd"
	dataStr, err := json.Marshal(user)
	if err != nil {
		log.Println(err.Error())
		return
	}
	tokenStr, err := generateToken(string(dataStr))
	if err != nil {
		log.Println(err.Error())
		return
	}
	var token Token
	token.Token = tokenStr
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}
func generateToken(dataStr string) (string, error) {
	log.Println("data " + dataStr)

	encryptedText, err := encryption.Encrypt([]byte(dataStr), []byte(key16))
	if err != nil {
		return "", err
	}
	fmt.Println(string(encryptedText))

	encoded64Text := base64.StdEncoding.EncodeToString([]byte(encryptedText))
	fmt.Println(encoded64Text)
	tokenStr, err := encode.Encode([]byte(encoded64Text), []byte(tokenKey))
	if err != nil {
		return "", err
	}
	fmt.Println(string(tokenStr))
	return string(tokenStr), nil
}
func ReadToken(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	userData, err := verifyToken(auth)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		//json.NewEncoder(w).Encode(err.Error)
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userData)
}
func verifyToken(auth string) (string, error) {
	token, err := encode.PrepareDecoding(auth)
	if err != nil {
		return "", err
	}
	fmt.Println("Prepare Decoding..")
	decodedString, err := encode.Decode([]byte(token), []byte(tokenKey))
	if err != nil {
		return "", err
	}
	fmt.Println(decodedString)
	fmt.Println("Decoded.")
	decoded64Text, err := base64.StdEncoding.DecodeString(decodedString)
	if err != nil {
		return "", err
	}
	fmt.Println("Decoded 64.")
	fmt.Println(string(decoded64Text))
	fmt.Println("Prepare Decrypting..")

	decryptedText, err := encryption.Decrypt([]byte(decoded64Text), []byte(key16))
	if err != nil {
		return "", err
	}
	fmt.Println("Decrypted")
	return string(decryptedText), nil
}
