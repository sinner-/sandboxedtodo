# sandboxed TODO

Had an idea about tiny webapps inspired by SQLite althttpd.

CGI maps closely to the original seccomp syscall sandboxing rules (read, write, exit only).

## Requirements

### Fedora

 * libseccomp-devel
 * mariadb-devel

### Ubuntu
 * libseccomp-dev
 * libmysqlclient-dev

## Compile

```gcc -o index main.c -lseccomp `mysql_config --cflags --libs````

## Run

```
cat <<EOF > server.py
import BaseHTTPServer
import CGIHTTPServer
import cgitb; cgitb.enable()  ## This line enables CGI error reporting

server = BaseHTTPServer.HTTPServer
handler = CGIHTTPServer.CGIHTTPRequestHandler
server_address = ("", 8000)
handler.cgi_directories = ["/"]

httpd = server(server_address, handler)
httpd.serve_forever()
EOF
python server.py
curl http://localhost:8000/index
```
