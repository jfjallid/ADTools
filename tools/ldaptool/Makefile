all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w" -o ldaptool

clean:
	rm -f ldaptool
