GO ?= go
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= /usr/share/logtool
SYSTEMD_DIR ?= /etc/systemd/system
ETC_DIR ?= /etc/logtool

.PHONY: all help build build-server build-importer build-pwhash install install-server install-importer install-ui systemd-install systemd-enable nginx-install clean

all: build

help:
	@echo "Targets:"
	@echo "  build             - Build all binaries"
	@echo "  build-server      - Build server binary (cmd/server)"
	@echo "  build-importer    - Build importer binary (cmd/importer)"
	@echo "  build-pwhash      - Build password hash util (cmd/pwhash)"
	@echo "  install           - Install binaries + UI (prefix=$(PREFIX))"
	@echo "  systemd-install   - Install systemd units + env examples"
	@echo "  systemd-enable    - Enable and start services/timer"
	@echo "  nginx-install     - Install nginx example to conf.d"
	@echo "  clean             - Remove built binaries"

build: build-server build-importer build-pwhash

build-server:
	$(GO) build -o ./bin/logtool-server ./cmd/server

build-importer:
	$(GO) build -o ./bin/logtool-importer ./cmd/importer

build-pwhash:
	$(GO) build -o ./bin/logtool-pwhash ./cmd/pwhash

install: build install-server install-importer install-ui

install-server:
	install -Dm755 ./bin/logtool-server $(BINDIR)/logtool-server

install-importer:
	install -Dm755 ./bin/logtool-importer $(BINDIR)/logtool-importer
	install -Dm755 ./bin/logtool-pwhash $(BINDIR)/logtool-pwhash

install-ui:
	install -d $(SHAREDIR)/web/dist
	cp -r web/dist/* $(SHAREDIR)/web/dist/

systemd-install:
	install -Dm644 deploy/systemd/logtool-server.service $(SYSTEMD_DIR)/logtool-server.service
	install -Dm644 deploy/systemd/logtool-importer.service $(SYSTEMD_DIR)/logtool-importer.service
	install -Dm644 deploy/systemd/logtool-importer.timer $(SYSTEMD_DIR)/logtool-importer.timer
	install -Dm644 deploy/systemd/server.env.example $(ETC_DIR)/server.env
	install -Dm644 deploy/systemd/importer.env.example $(ETC_DIR)/importer.env

systemd-enable:
	systemctl daemon-reload
	systemctl enable --now logtool-server
	systemctl enable --now logtool-importer.timer

nginx-install:
	install -Dm644 deploy/nginx/logtool.conf /etc/nginx/conf.d/logtool.conf
	@echo "Reload nginx: systemctl reload nginx"

clean:
	rm -rf ./bin

