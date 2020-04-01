package main

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	cristalhq "github.com/cristalhq/jwt"
	dgrijalva "github.com/dgrijalva/jwt-go"
	gbrlsnchs "github.com/gbrlsnchs/jwt/v3"
	"github.com/lestrrat-go/jwx/jwa"
	lestrrat "github.com/lestrrat-go/jwx/jwt"
	pascaldekloe "github.com/pascaldekloe/jwt"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
)

type DgrijalvaToken struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	dgrijalva.StandardClaims
}

type PascaldekloeToken struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	pascaldekloe.Claims
}

type GbrlsnchsToken struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	gbrlsnchs.Payload
}

type CristalhqToken struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	cristalhq.StandardClaims
}

var dgrijalvaToken DgrijalvaToken
var pascaldekloeToken PascaldekloeToken
var gbrlsnchsToken GbrlsnchsToken
var cristalhqToken CristalhqToken
var lestrratToken lestrrat.Token

func init() {
	log.SetFlags(log.Lshortfile)
	err := loadKey()
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	dgrijalvaToken.Data.ID = "12345"
	dgrijalvaToken.Data.Username = "dxvgef"

	pascaldekloeToken.Data.ID = "12345"
	pascaldekloeToken.Data.Username = "dxvgef"

	gbrlsnchsToken.Data.ID = "12345"
	gbrlsnchsToken.Data.Username = "dxvgef"

	cristalhqToken.Data.ID = "12345"
	cristalhqToken.Data.Username = "dxvgef"

	if err = lestrratToken.Set("id", "12345"); err != nil {
		log.Fatalln(err.Error())
	}
	if err = lestrratToken.Set("username", "dxvgef"); err != nil {
		log.Fatalln(err.Error())
	}
}

func loadKey() error {
	// 读取公钥
	publicKeyByte, err := ioutil.ReadFile("./public.key")
	if err != nil {
		log.Println(err.Error())
		return err
	}
	publicKey, err = dgrijalva.ParseRSAPublicKeyFromPEM(publicKeyByte)
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
	privateKey, err = dgrijalva.ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	return nil
}

func keyFunc(token *dgrijalva.Token) (interface{}, error) {
	if _, ok := token.Method.(*dgrijalva.SigningMethodRSA); !ok {
		return nil, errors.New("验证Token的加密类型错误")
	}
	return publicKey, nil
}

func Benchmark_dgrijalva(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dgrijalvaToken.ExpiresAt = time.Now().Add(3 * time.Second).Unix()
		token := dgrijalva.NewWithClaims(dgrijalva.SigningMethodRS256, dgrijalvaToken)
		tokenStr, err := token.SignedString(privateKey)
		if err != nil {
			b.Error(err)
			return
		}

		// 用公钥验证Token合法性，并解析出一个token对象的指针
		token2, err := dgrijalva.ParseWithClaims(tokenStr, &DgrijalvaToken{}, keyFunc)
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

func Benchmark_pascaldekloe(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pascaldekloeToken.Expires = pascaldekloe.NewNumericTime(time.Now().Add(3 * time.Second))
		tokenBytes, err := pascaldekloeToken.RSASign(pascaldekloe.RS256, privateKey)
		if err != nil {
			b.Error(err)
			return
		}
		_ = string(tokenBytes)

		_, err = pascaldekloe.RSACheck(tokenBytes, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func Benchmark_gbrlsnchs(b *testing.B) {
	rs := gbrlsnchs.NewRS256(
		gbrlsnchs.RSAPublicKey(publicKey),
		gbrlsnchs.RSAPrivateKey(privateKey),
	)
	for i := 0; i < b.N; i++ {
		gbrlsnchsToken.ExpirationTime = gbrlsnchs.NumericDate(time.Now().Add(3 * time.Second))
		tokenBytes, err := gbrlsnchs.Sign(gbrlsnchsToken, rs)
		if err != nil {
			b.Error(err)
			return
		}
		_ = string(tokenBytes)

		var token GbrlsnchsToken
		_, err = gbrlsnchs.Verify(tokenBytes, rs, &token)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func Benchmark_cristalhq(b *testing.B) {
	signer, err := cristalhq.NewRS256(publicKey, privateKey)
	if err != nil {
		b.Error(err.Error())
		return
	}
	for i := 0; i < b.N; i++ {
		cristalhqToken.ExpiresAt = cristalhq.Timestamp(time.Now().Add(3 * time.Second).Unix())
		newToken, err := cristalhq.Build(signer, cristalhqToken)
		if err != nil {
			b.Error(err)
			return
		}

		_, err = cristalhq.ParseAndVerify(newToken.Raw(), signer)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

func Benchmark_lestrrat(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := lestrratToken.Set(lestrrat.ExpirationKey, time.Now().Add(3 * time.Second).Unix())
		if err != nil {
			b.Error(err.Error())
			return
		}
		tokenBytes, err := lestrratToken.Sign(jwa.RS256, privateKey)
		if err != nil {
			b.Error(err)
			return
		}
		_, err = lestrrat.ParseVerify(bytes.NewReader(tokenBytes), jwa.RS256, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
	}
}