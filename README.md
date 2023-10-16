# go-jwt-benchmark
常用 Go 语言的 JWT 包的性能测试代码

```
go test -bench=. -benchmem
```

根据测试结果，目前综合性能最好的是 `pascaldekloe/jwt`

```
goos: darwin
goarch: arm64
Benchmark_cristalhq_sign-8                   799           1495606 ns/op            2049 B/op         14 allocs/op
Benchmark_cristalhq_verify-8                5690            210688 ns/op            1952 B/op         18 allocs/op
Benchmark_gbrlsnchs_sign-8                   800           1498400 ns/op            3036 B/op         19 allocs/op
Benchmark_gbrlsnchs_verify-8                5641            212028 ns/op            3206 B/op         32 allocs/op
Benchmark_golangjwt_sign-8                   794           1504902 ns/op            3609 B/op         31 allocs/op
Benchmark_golangjwt_verify-8                5581            213915 ns/op            4744 B/op         59 allocs/op
Benchmark_pascaldekloe_sign-8                801           1495566 ns/op            1417 B/op          8 allocs/op
Benchmark_pascaldekloe_verify-8             5698            211580 ns/op            2056 B/op         22 allocs/op
```
