PREFIX ?= /usr/local/bin

canary: $(wildcard *.go)
	go build -o canary .

install: canary
	install -m 755 canary $(PREFIX)/canary

uninstall:
	rm -f $(PREFIX)/canary

clean:
	rm -f canary

.PHONY: install uninstall clean
