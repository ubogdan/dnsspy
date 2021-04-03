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
interface=lo, bpf filter=udp and port 53
----------------------------------------------------------------
Type  Query                            SrcIP            Response
----- -------------------------------- ---------------- --------
A     vortex.data.microsoft.com        127.0.0.53       CNAME asimov.vortex.data.trafficmanager.net
                                                        64.4.54.254
AAAA  vortex.data.microsoft.com        127.0.0.53       CNAME asimov.vortex.data.trafficmanager.net
                                                        CNAME global.vortex.data.trafficmanager.net
A     d.dropbox.com                    127.0.0.53       CNAME d.v.dropbox.com
                                                        CNAME d-edge.v.dropbox.com
                                                        162.125.6.20
```
