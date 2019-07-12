# go-jwt-benchmark
Benchmark for the JWT package developed by golang


Tested packages
```
github.com/dgrijalva/jwt-go
github.com/pascaldekloe/jwt
```


Run:
```
go test -bench=.
```

Result:
```
goos: darwin
goarch: amd64
BenchmarkTokenA-4           1000           1631557 ns/op
BenchmarkTokenB-4           1000           1622243 ns/op
```