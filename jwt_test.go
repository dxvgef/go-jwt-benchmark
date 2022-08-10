package main

import (
	"crypto/rsa"
	"log"
	"os"
	"testing"
	"time"

	cristalhq "github.com/cristalhq/jwt/v4"
	dgrijalva "github.com/dgrijalva/jwt-go"
	gbrlsnchs "github.com/gbrlsnchs/jwt/v3"
	golangjwt "github.com/golang-jwt/jwt/v4"
	pascaldekloe "github.com/pascaldekloe/jwt"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	tokenStr   string
	tokenBytes []byte
)

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
	// claims.ExpiresAt = cristalhq.NewNumericDate(time.Now().Add(3 * time.Second))

	for i := 0; i < b.N; i++ {
		signer, err = cristalhq.NewSignerRS(cristalhq.RS256, privateKey)
		if err != nil {
			b.Errorf(err.Error())
			return
		}
		token, err = cristalhq.NewBuilder(signer).Build(claims)
		if err != nil {
			b.Error(err)
			return
		}
		tokenStr = bytesToStr(token.Bytes())
	}
	tokenBytes = strToBytes(tokenStr)
}

func Benchmark_cristalhq_verify(b *testing.B) {
	var (
		err      error
		verifier *cristalhq.RSAlg
	)
	for i := 0; i < b.N; i++ {
		verifier, err = cristalhq.NewVerifierRS(cristalhq.RS256, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
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
	// claims.ExpiresAt = time.Now().Add(3 * time.Second).Unix()

	for i := 0; i < b.N; i++ {
		token = dgrijalva.NewWithClaims(dgrijalva.SigningMethodRS256, claims)
		tokenStr, err = token.SignedString(privateKey)
		if err != nil {
			b.Error(err)
			return
		}
	}

	tokenBytes = strToBytes(tokenStr)
}

func Benchmark_dgrijalva_verify(b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		_, err = dgrijalva.Parse(tokenStr, func(tk *dgrijalva.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// --------------------------- end dgrijalva ----------------------------------

// ----------------------------------- begin gbrlsnchs ------------------------------
func Benchmark_gbrlsnchs_sign(b *testing.B) {
	type Token struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		gbrlsnchs.Payload
	}
	var (
		err   error
		token Token
		alg   *gbrlsnchs.RSASHA
	)
	token.Data.ID = "12345"
	token.Data.Username = "dxvgef"
	// token.ExpirationTime = gbrlsnchs.NumericDate(time.Now().Add(3 * time.Second))

	for i := 0; i < b.N; i++ {
		alg = gbrlsnchs.NewRS256(
			gbrlsnchs.RSAPublicKey(publicKey),
			gbrlsnchs.RSAPrivateKey(privateKey),
		)
		tokenBytes, err = gbrlsnchs.Sign(token, alg)
		if err != nil {
			b.Error(err)
			return
		}
	}
	tokenStr = bytesToStr(tokenBytes)
}

func Benchmark_gbrlsnchs_verify(b *testing.B) {
	type Token struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		gbrlsnchs.Payload
	}
	var (
		err   error
		token Token
		alg   *gbrlsnchs.RSASHA
	)
	for i := 0; i < b.N; i++ {
		alg = gbrlsnchs.NewRS256(
			gbrlsnchs.RSAPublicKey(publicKey),
			gbrlsnchs.RSAPrivateKey(privateKey),
		)
		_, err = gbrlsnchs.Verify(tokenBytes, alg, &token)
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// ----------------------------------- end gbrlsnchs ------------------------------

// --------------------------- begin golangjwt ----------------------------------
func Benchmark_golangjwt_sign(b *testing.B) {
	type Claims struct {
		Data struct {
			ID       string `json:"id,omitempty"`
			Username string `json:"username,omitempty"`
		} `json:"data,omitempty"`
		golangjwt.RegisteredClaims
	}
	var (
		err    error
		claims Claims
		token  *golangjwt.Token
	)
	claims.Data.ID = "12345"
	claims.Data.Username = "dxvgef"
	// claims.ExpiresAt = golangjwt.NewNumericDate(time.Now().Add(3 * time.Second))
	for i := 0; i < b.N; i++ {
		token = golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, claims)
		tokenStr, err = token.SignedString(privateKey)
		if err != nil {
			b.Error(err)
			return
		}
	}
	tokenBytes = strToBytes(tokenStr)
}

func Benchmark_golangjwt_verify(b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		_, err = golangjwt.Parse(tokenStr, func(tk *golangjwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Error(err)
			return
		}
	}
}

// --------------------------- end golangjwt ----------------------------------

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
	// token.Expires = pascaldekloe.NewNumericTime(time.Now().Add(3 * time.Second))

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
	var (
		err   error
		token *pascaldekloe.Claims
	)
	for i := 0; i < b.N; i++ {
		token, err = pascaldekloe.RSACheck(tokenBytes, publicKey)
		if err != nil {
			b.Error(err)
			return
		}
		token.Valid(time.Now())
	}
}

// --------------------------- end pascaldekloe -----------------------------------
