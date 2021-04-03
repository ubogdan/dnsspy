# Simple DNS traffic spy in Go

Go version of [DNSPeep](https://github.com/jvns/dnspeep/blob/f5780dc822df5151f83703f05c767dad830bd3b2/src/main.rs). 

You can read more about `dnspeep` and Rust in Julia Evans [blog post](https://jvns.ca/blog/2021/03/31/dnspeep-tool/).

Rust version [src](https://github.com/jvns/dnspeep/blob/f5780dc822df5151f83703f05c767dad830bd3b2/src/main.rs).


## Requirements

```bash
$ sudo apt install libpcap-dev
```

## Build

```bash
$ go build main.go
```

## Run
``` bash
$ sudo ./main
* Filter:  udp and port 53
A     api.openweathermap.org           127.0.0.53       192.241.167.16
                                                        192.241.187.136
                                                        192.241.245.161
A     api.openweathermap.org           127.0.0.53       192.241.167.16
                                                        192.241.187.136
                                                        192.241.245.161
```
