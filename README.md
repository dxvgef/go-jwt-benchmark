# go-jwt-benchmark
常用 Go 语言的 JWT 包的性能测试代码

```
go test -bench=. -benchmem
```

注意： `dgrijalva/jwt-go` 的 `<=3.2.0` 版本存在安全漏洞，建议使用 `golang-jwt/jwt` 替代。

根据测试结果，目前综合性能最好的是 `cristalhq/jwt/v4`

```
goos: darwin
goarch: arm64
pkg: github.com/dxvgef/jwt-benchmark
Benchmark_cristalhq_sign-8                  1179           1019143 ns/op           31561 B/op        117 allocs/op
Benchmark_cristalhq_verify-8               40951             29302 ns/op            6043 B/op         22 allocs/op
Benchmark_dgrijalva_sign-8                  1171           1021674 ns/op           33100 B/op        134 allocs/op
Benchmark_dgrijalva_verify-8               38052             30873 ns/op            9141 B/op         66 allocs/op
Benchmark_gbrlsnchs_sign-8                  1173           1020884 ns/op           32553 B/op        122 allocs/op
Benchmark_gbrlsnchs_verify-8               39816             30193 ns/op            7296 B/op         36 allocs/op
Benchmark_golangjwt_sign-8                  1170           1016995 ns/op           33104 B/op        134 allocs/op
Benchmark_golangjwt_verify-8               39010             30745 ns/op            8724 B/op         63 allocs/op
Benchmark_pascaldekloe_sign-8               1158           1018980 ns/op           30926 B/op        111 allocs/op
Benchmark_pascaldekloe_verify-8            40502             29635 ns/op            6147 B/op         26 allocs/op
PASS
ok      github.com/dxvgef/jwt-benchmark 15.891s
```
