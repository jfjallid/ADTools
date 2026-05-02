TOOLS=$(shell ls tools/)

all: build

build:
	@mkdir -p bin/
	@for tool in $(TOOLS); do \
		echo "[*] Building $$tool..."; \
		if [ -f "tools/$$tool/Makefile" ]; then \
			$(MAKE) -C "tools/$$tool" && \
			mv "tools/$$tool/$$tool" bin/; \
		else \
			CGO_ENABLED=0 go build -o bin/$$tool --ldflags "-s -w" tools/$$tool/main.go; \
		fi; \
	done

clean:
	rm -rf bin/

.PHONY: all build clean
