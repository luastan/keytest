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

### Other options

In any mode you can specify the number of workers. The workers are goroutines, so you can specify relatively high values.
The main concern is on some OSes, where the number of open file descriptors is capped (around 1024).
So take in mind every worker will have 1 file descriptor open.
Default value is `100`, but you can change it with the `--workers` option.

````shell
keytest check DIR --workers 200
````

## Installation

With `go install`:

```shell
go install github.com/luastan/keytest@latest
```