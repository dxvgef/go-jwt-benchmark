# go-jwt-benchmark
Benchmark for the JWT package developed by golang


Tested packages
```
JWTA github.com/dgrijalva/jwt-go
JWTB github.com/pascaldekloe/jwt
JWTC github.com/gbrlsnchs/jwt/v3
```


Run:
```
go test -bench=.
```

Result:
```
goos: darwin
goarch: amd64
BenchmarkJWTA-4           1000           1636959 ns/op
BenchmarkJWTB-4           1000           1629493 ns/op
BenchmarkJWTC-4           1000           1631967 ns/op
```