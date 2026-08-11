.PHONY: build run setcap test lint clean

BINARY_NAME=undertow

build:
	go build -o $(BINARY_NAME) ./cmd/undertow

run: build
	sudo ./$(BINARY_NAME) -i eth0

setcap: build
	sudo setcap cap_net_raw,cap_net_admin=eip ./$(BINARY_NAME)

test:
	go test -race -v ./internal/...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
