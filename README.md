# KeyTest

Find and test API keys


## Usage


### Find keys

List every single API key and its location
```shell
keytest check DIR
```


### Find & check keys


Find and perform every available check to any API key found with `keytest check`:
```shell
keytest check DIR
```

The results can be saved to a markdown file:

```shell
keytest check DIR -o results.md
```

Input can also come from _stdin_:

```shell
cat some_file.txt | keytest check
```

Use of a proxy is also possible through **HTTP** or **SOCKS5**:
```shell
keytest check DIR --upstream-proxy socks5://127.0.0.1:2222
```


## Installation

With `go get`:

```shell
go get -u github.com/luastan/keytest
```