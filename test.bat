go mod tidy
cd cmd\caddy\
go mod tidy
go build -o caddy.exe .
cd ..\..\
.\cmd\caddy\caddy.exe run --config test\Caddyfile --adapter caddyfile

rem curl -v -H "Host: dom.localhost" http://localhost:8080/