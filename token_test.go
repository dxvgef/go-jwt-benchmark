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
	jwtC "github.com/gbrlsnchs/jwt/v3"
	jwtB "github.com/pascaldekloe/jwt"
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

type TokenC struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	jwtC.Payload
}

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey

var tokenA TokenA
var tokenB TokenB
var tokenC TokenC

func init() {
	log.SetFlags(log.Lshortfile)

	// 读取公钥
	publicKeyByte, err := ioutil.ReadFile("./public.key")
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	// 读取私钥
	privateKeyByte, err := ioutil.ReadFile("./private.key")
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	publicKey, err = ParseRSAPublicKeyFromPEM(publicKeyByte)
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	privateKey, err = ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	tokenA.Data.ID = "12345"
	tokenA.Data.Username = "dxvgef"

	tokenB.Data.ID = "12345"
	tokenB.Data.Username = "dxvgef"

	tokenC.Data.ID = "12345"
	tokenC.Data.Username = "dxvgef"
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

func BenchmarkTokenC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tokenC.ExpirationTime = jwtC.NumericDate(time.Now().Add(3 * time.Second))
		rsasha := jwtC.NewRS256(jwtC.RSAPrivateKey(privateKey))
		tokenBytes, err := jwtC.Sign(tokenC, rsasha)
		if err != nil {
			b.Error(err)
			return
		}

		var tokenCC TokenC
		_, err = jwtC.Verify(tokenBytes, rsasha, &tokenCC)
		if err != nil {
			b.Error(err)
			return
		}
	}
}
