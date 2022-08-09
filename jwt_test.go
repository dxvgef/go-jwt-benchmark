package main

import (
	"crypto/rsa"
	"errors"
	"log"
	"os"
	"testing"
	"time"

	cristalhq "github.com/cristalhq/jwt/v4"
	dgrijalva "github.com/dgrijalva/jwt-go"
	gbrlsnchs "github.com/gbrlsnchs/jwt/v3"
	pascaldekloe "github.com/pascaldekloe/jwt"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	tokenStr   string
	tokenBytes []byte
)

type GbrlsnchsToken struct {
	Data struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
	} `json:"data,omitempty"`
	gbrlsnchs.Payload
}

func keyFunc(token *dgrijalva.Token) (interface{}, error) {
	if _, ok := token.Method.(*dgrijalva.SigningMethodRSA); !ok {
		return nil, errors.New("验证Token的加密类型错误")
	}
	return publicKey, nil
}

func init() {
	log.SetFlags(log.Lshortfile)

	// 读取公钥
	publicKeyByte, err := os.ReadFile("./public.key")
	if err != nil {
		log.Println(err.Error())
		return
	}
	publicKey, err = dgrijalva.ParseRSAPublicKeyFromPEM(publicKeyByte)
	if err != nil {
		log.Println(err.Error())
		return
	}

	// 读取私钥
	privateKeyByte, err := os.ReadFile("./private.key")
	if err != nil {
		log.Println(err.Error())
		return
	}
	privateKey, err = dgrijalva.ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		log.Println(err.Error())
		return
	}
}

// --------------------------- begin cristalhq -----------------------------------
func Benchmark_cristalhq_sign(b *testing.B) {
	type Claims struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		cristalhq.RegisteredClaims
	}

	var (
		err    error
		claims Claims
		signer *cristalhq.RSAlg
		token  *cristalhq.Token
	)

	claims.Data.ID = "12345"
	claims.Data.Username = "dxvgef"
	claims.ExpiresAt = cristalhq.NewNumericDate(time.Now().Add(3 * time.Second))

	signer, err = cristalhq.NewSignerRS(cristalhq.RS256, privateKey)
	if err != nil {
		b.Errorf(err.Error())
		return
	}

	for i := 0; i < b.N; i++ {
		token, err = cristalhq.NewBuilder(signer).Build(claims)
		if err != nil {
			b.Error(err)
			return
		}
	}
	tokenStr = bytesToStr(token.Bytes())
	tokenBytes = token.Bytes()
}

func Benchmark_cristalhq_verify(b *testing.B) {
	verifier, err := cristalhq.NewVerifierRS(cristalhq.RS256, publicKey)
	if err != nil {
		b.Error(err)
		return
	}
	for i := 0; i < b.N; i++ {
		_, err = cristalhq.Parse(tokenBytes, verifier)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// --------------------------- end cristalhq -----------------------------------

// --------------------------- begin dgrijalva ----------------------------------
func Benchmark_dgrijalva_sign(b *testing.B) {
	type Claims struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		dgrijalva.StandardClaims
	}
	var (
		err    error
		claims Claims
		token  *dgrijalva.Token
	)
	claims.Data.ID = "12345"
	claims.Data.Username = "dxvgef"
	claims.ExpiresAt = time.Now().Add(3 * time.Second).Unix()
	token = dgrijalva.NewWithClaims(dgrijalva.SigningMethodRS256, claims)

	for i := 0; i < b.N; i++ {
		tokenStr, err = token.SignedString(privateKey)
		if err != nil {
			b.Error(err)
			return
		}
	}

	tokenBytes = strToBytes(tokenStr)
}

func Benchmark_dgrijalva_verify(b *testing.B) {
	type Claims struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		dgrijalva.StandardClaims
	}
	for i := 0; i < b.N; i++ {
		token, err := dgrijalva.ParseWithClaims(tokenStr, &Claims{}, keyFunc)
		if err != nil {
			b.Error(err)
			return
		}
		// 验证token是否有效
		err = token.Claims.Valid()
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// --------------------------- end dgrijalva ----------------------------------

// --------------------------- begin pascaldekloe -----------------------------------
func Benchmark_pascaldekloe_sign(b *testing.B) {
	type Token struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		pascaldekloe.Claims
	}

	var (
		err   error
		token Token
	)
	token.Data.ID = "12345"
	token.Data.Username = "dxvgef"
	token.Expires = pascaldekloe.NewNumericTime(time.Now().Add(3 * time.Second))

	for i := 0; i < b.N; i++ {
		tokenBytes, err = token.RSASign(pascaldekloe.RS256, privateKey)
		if err != nil {
			b.Error(err)
			return
		}
	}
	tokenStr = bytesToStr(tokenBytes)
}

func Benchmark_pascaldekloe_verify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := pascaldekloe.RSACheck(tokenBytes, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// --------------------------- end pascaldekloe -----------------------------------

// ----------------------------------- begin gbrlsnchs ------------------------------
func Benchmark_gbrlsnchs_sign(b *testing.B) {
	var (
		err   error
		token GbrlsnchsToken
	)
	token.Data.ID = "12345"
	token.Data.Username = "dxvgef"
	token.ExpirationTime = gbrlsnchs.NumericDate(time.Now().Add(3 * time.Second))

	gbrlsnchsAlg := gbrlsnchs.NewRS256(
		gbrlsnchs.RSAPublicKey(publicKey),
		gbrlsnchs.RSAPrivateKey(privateKey),
	)

	for i := 0; i < b.N; i++ {
		tokenBytes, err = gbrlsnchs.Sign(token, gbrlsnchsAlg)
		if err != nil {
			b.Error(err)
			return
		}
	}
	tokenStr = bytesToStr(tokenBytes)
}

func Benchmark_gbrlsnchs_verify(b *testing.B) {
	var token GbrlsnchsToken
	gbrlsnchsAlg := gbrlsnchs.NewRS256(
		gbrlsnchs.RSAPublicKey(publicKey),
		gbrlsnchs.RSAPrivateKey(privateKey),
	)
	for i := 0; i < b.N; i++ {
		_, err := gbrlsnchs.Verify(tokenBytes, gbrlsnchsAlg, &token)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// ----------------------------------- end gbrlsnchs ------------------------------
