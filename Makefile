NAME := keepass-vault-sync

bin/${NAME}: bin-dir
	go build -o bin/${NAME} .

bin: bin-dir bin/${NAME}
.PHONY: bin

bin-dir:
	mkdir -p bin
.PHONY: bin-dir