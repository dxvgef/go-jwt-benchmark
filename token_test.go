package main

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	jwtA "github.com/dgrijalva/jwt-go"
	jwtB "github.com/pascaldekloe/jwt"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
)

type TokenA struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	jwtA.StandardClaims
}

type TokenB struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	jwtB.Claims
}

var tokenA TokenA
var tokenB TokenB

func init() {
	log.SetFlags(log.Lshortfile)
	err := loadKey()
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	tokenA.Data.ID = "12345"
	tokenA.Data.Username = "dxvgef"

	tokenB.Data.ID = "12345"
	tokenB.Data.Username = "dxvgef"
}

func loadKey() error {
	// 读取公钥
	publicKeyByte, err := ioutil.ReadFile("./public.key")
	if err != nil {
		log.Println(err.Error())
		return err
	}
	publicKey, err = jwtA.ParseRSAPublicKeyFromPEM(publicKeyByte)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	// 读取私钥
	privateKeyByte, err := ioutil.ReadFile("./private.key")
	if err != nil {
		log.Println(err.Error())
		return err
	}
	privateKey, err = jwtA.ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	return nil
}

func keyFunc(token *jwtA.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwtA.SigningMethodRSA); !ok {
		return nil, errors.New("验证Token的加密类型错误")
	}
	return publicKey, nil
}

func BenchmarkTokenA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tokenA.ExpiresAt = time.Now().Add(3 * time.Second).Unix()
		token := jwtA.NewWithClaims(jwtA.SigningMethodRS256, tokenA)
		tokenStr, err := token.SignedString(privateKey)
		if err != nil {
			b.Error(err)
			return
		}

		// 用公钥验证Token合法性，并解析出一个token对象的指针
		token2, err := jwtA.ParseWithClaims(tokenStr, &TokenA{}, keyFunc)
		if err != nil {
			b.Error(err)
			return
		}

		// 验证token是否有效
		err = token2.Claims.Valid()
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func BenchmarkTokenB(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tokenB.Expires = jwtB.NewNumericTime(time.Now().Add(3 * time.Second))
		tokenBytes, err := tokenB.RSASign(jwtB.RS256, privateKey)
		if err != nil {
			b.Error(err)
			return
		}
		_ = string(tokenBytes)

		token, err := jwtB.RSACheck(tokenBytes, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
		token.Valid(time.Now())
	}
}
