# go-jwt-benchmark
常用 Go 语言的 JWT 包的性能测试代码

```
go test -bench=. -benchmem
```

注意： `dgrijalva/jwt-go` 的 `<=3.2.0` 版本存在安全漏洞，建议使用 `golang-jwt/jwt` 替代。

根据测试结果，目前综合性能最好的是 `pascaldekloe/jwt`

```
goos: darwin
goarch: arm64
pkg: github.com/dxvgef/jwt-benchmark
Benchmark_cristalhq_sign-8                   952           1251525 ns/op            2049 B/op         14 allocs/op
Benchmark_cristalhq_verify-8                7273            164319 ns/op            2016 B/op         18 allocs/op
Benchmark_dgrijalva_sign-8                   956           1247451 ns/op            3593 B/op         31 allocs/op
Benchmark_dgrijalva_verify-8                7168            166362 ns/op            5112 B/op         62 allocs/op
Benchmark_gbrlsnchs_sign-8                   958           1243768 ns/op            3043 B/op         19 allocs/op
Benchmark_gbrlsnchs_verify-8                7297            164801 ns/op            3268 B/op         32 allocs/op
Benchmark_golangjwt_sign-8                   957           1247416 ns/op            3593 B/op         31 allocs/op
Benchmark_golangjwt_verify-8                7202            166082 ns/op            4696 B/op         59 allocs/op
Benchmark_pascaldekloe_sign-8                956           1248893 ns/op            1417 B/op          8 allocs/op
Benchmark_pascaldekloe_verify-8             7074            165063 ns/op            2120 B/op         22 allocs/op
PASS
ok      github.com/dxvgef/jwt-benchmark 12.649s
```
