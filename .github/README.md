# passt: Plug A Simple Socket Transport

See https://passt.top/passt/about/ for the original repository.

This branch is mainly dedicated to the proxy feature:

```sh
$ ./pasta --help
...
  --dns-redirect ADDR   Redirect DNS queries sent to ADDR
    can be specified zero to two times (for IPv4 and IPv6)
    default: don't redirect DNS queries
  --proxy ADDR:PORT     Specify proxy address and port
    default: don't use any proxy
  --proxy-type TYPE     Specify proxy type: socks5|http|socks4
    default: socks5 if proxy has been set
  --proxy-user NAME     username for proxy authentication
  --proxy-passwd PWD    password for proxy authentication
...
```

Example:

```sh
./pasta --proxy="127.0.0.1:7890" --proxy-type=http wget https://example.com
```

When --proxy-type is set to socks5, UDP is supported:

```sh
./pasta --proxy="127.0.0.1:7890" --proxy-type=socks5 uip
```

The above [uip](https://github.com/dndx/uip) tool can be used to test UDP forwarding.

To specify DNS, the "--dns-redirect" option can be used:

```sh
./pasta --dns-redirect="1.1.1.1" --proxy="127.0.0.1:7890" --proxy-type=socks5 bash
```
