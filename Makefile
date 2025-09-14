GO ?= go
# Disable VCS stamping to avoid errors when not in a git repo
GOFLAGS ?= -buildvcs=false
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= /usr/share/logtool
SYSTEMD_DIR ?= /etc/systemd/system
ETC_DIR ?= /etc/logtool
DATADIR ?= /var/lib/logtool
# Service runtime options
RUN_USER ?=
RUN_GROUP ?=
SUPP_GROUPS ?=
DYNAMIC_USER ?= yes
# Service runtime params
ADDR ?= :8080
TZ ?= +00:00
ACCESS_LOG ?= /var/log/nginx/access.log
ERROR_LOG ?= /var/log/nginx/error.log

.PHONY: all help print-config build build-server build-importer build-pwhash install install-server install-importer install-ui systemd-install systemd-config systemd-enable nginx-install clean

all: build

help:
	@echo "Targets:"
	@echo "  build             - Build all binaries"
	@echo "  build-server      - Build server binary (cmd/server)"
	@echo "  build-importer    - Build importer binary (cmd/importer)"
	@echo "  build-pwhash      - Build password hash util (cmd/pwhash)"
	@echo "  install           - Install binaries + UI (prefix=$(PREFIX))"
	@echo "  systemd-install   - Install systemd units + env examples"
	@echo "  systemd-config    - Generate systemd drop-in overrides (paths/users)"
	@echo "  systemd-enable    - Enable and start services/timer"
	@echo "  nginx-install     - Install nginx example to conf.d"
	@echo "  print-config      - Print resolved install variables"
	@echo "  clean             - Remove built binaries"
	@echo
	@echo "Variables (override like VAR=value):"
	@echo "  PREFIX=$(PREFIX)  BINDIR=$(BINDIR)  SHAREDIR=$(SHAREDIR)  SYSTEMD_DIR=$(SYSTEMD_DIR)  ETC_DIR=$(ETC_DIR)"
	@echo "  DATADIR=$(DATADIR)  RUN_USER=$(RUN_USER)  RUN_GROUP=$(RUN_GROUP)  SUPP_GROUPS=$(SUPP_GROUPS)  DYNAMIC_USER=$(DYNAMIC_USER)"
	@echo "  ADDR=$(ADDR)  TZ=$(TZ)  ACCESS_LOG=$(ACCESS_LOG)  ERROR_LOG=$(ERROR_LOG)"

print-config:
	@echo "PREFIX=$(PREFIX)"
	@echo "BINDIR=$(BINDIR)"
	@echo "SHAREDIR=$(SHAREDIR)"
	@echo "SYSTEMD_DIR=$(SYSTEMD_DIR)"
	@echo "ETC_DIR=$(ETC_DIR)"
	@echo "DATADIR=$(DATADIR)"
	@echo "RUN_USER=$(RUN_USER)"
	@echo "RUN_GROUP=$(RUN_GROUP)"
	@echo "SUPP_GROUPS=$(SUPP_GROUPS)"
	@echo "DYNAMIC_USER=$(DYNAMIC_USER)"
	@echo "ADDR=$(ADDR)  TZ=$(TZ)"
	@echo "ACCESS_LOG=$(ACCESS_LOG)"
	@echo "ERROR_LOG=$(ERROR_LOG)"

build: build-server build-importer build-pwhash

build-server:
	$(GO) build $(GOFLAGS) -o ./bin/logtool-server ./cmd/server

build-importer:
	$(GO) build $(GOFLAGS) -o ./bin/logtool-importer ./cmd/importer

build-pwhash:
	$(GO) build $(GOFLAGS) -o ./bin/logtool-pwhash ./cmd/pwhash

install: build install-server install-importer install-ui
	# Ensure data directory exists with secure perms; set owner if provided
	install -d -m 0750 $(INSTALL_OWNER_FLAGS) $(DATADIR)

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

# Build owner flags for install(1)
INSTALL_OWNER_FLAGS :=
ifneq ($(strip $(RUN_USER)),)
INSTALL_OWNER_FLAGS += -o $(RUN_USER)
endif
ifneq ($(strip $(RUN_GROUP)),)
INSTALL_OWNER_FLAGS += -g $(RUN_GROUP)
endif

# Generate drop-in overrides to customize paths/users without editing shipped units
systemd-config:
	@set -e; \
	SERVER_DIR="$(SYSTEMD_DIR)/logtool-server.service.d"; \
	IMPORTER_DIR="$(SYSTEMD_DIR)/logtool-importer.service.d"; \
	SERVER_DROP="$$SERVER_DIR/override.conf"; \
	IMPORTER_DROP="$$IMPORTER_DIR/override.conf"; \
	mkdir -p "$$SERVER_DIR" "$$IMPORTER_DIR"; \
	if [ -f "$$SERVER_DROP" ] && [ -z "$(FORCE)" ]; then echo "Refusing to overwrite $$SERVER_DROP (use FORCE=1)"; exit 1; fi; \
	if [ -f "$$IMPORTER_DROP" ] && [ -z "$(FORCE)" ]; then echo "Refusing to overwrite $$IMPORTER_DROP (use FORCE=1)"; exit 1; fi; \
	printf "[Service]\n" >"$$SERVER_DROP"; \
	printf "Environment=LOGTOOL_DB=$(DATADIR)/monitor.db\n" >>"$$SERVER_DROP"; \
	printf "Environment=LOGTOOL_STATIC=$(SHAREDIR)/web/dist\n" >>"$$SERVER_DROP"; \
	printf "Environment=LOGTOOL_ADDR=$(ADDR)\n" >>"$$SERVER_DROP"; \
	printf "Environment=LOGTOOL_TZ=$(TZ)\n" >>"$$SERVER_DROP"; \
	printf "ReadWritePaths=$(DATADIR)\n" >>"$$SERVER_DROP"; \
	if [ "$(strip $(DYNAMIC_USER))" = "no" ]; then printf "DynamicUser=no\n" >>"$$SERVER_DROP"; fi; \
	if [ -n "$(strip $(RUN_USER))" ]; then printf "User=$(RUN_USER)\n" >>"$$SERVER_DROP"; fi; \
	if [ -n "$(strip $(RUN_GROUP))" ]; then printf "Group=$(RUN_GROUP)\n" >>"$$SERVER_DROP"; fi; \
	if [ -n "$(strip $(SUPP_GROUPS))" ]; then printf "SupplementaryGroups=$(SUPP_GROUPS)\n" >>"$$SERVER_DROP"; fi; \
	printf "ExecStart=\n" >>"$$SERVER_DROP"; \
	printf "ExecStart=$(BINDIR)/logtool-server -db $$LOGTOOL_DB -addr $$LOGTOOL_ADDR -tz $$LOGTOOL_TZ -static $$LOGTOOL_STATIC\n" >>"$$SERVER_DROP"; \
	echo "Wrote $$SERVER_DROP"; \
	printf "[Service]\n" >"$$IMPORTER_DROP"; \
	printf "Environment=LOGTOOL_DB=$(DATADIR)/monitor.db\n" >>"$$IMPORTER_DROP"; \
	printf "Environment=LOGTOOL_ACCESS=$(ACCESS_LOG)\n" >>"$$IMPORTER_DROP"; \
	printf "Environment=LOGTOOL_ERROR=$(ERROR_LOG)\n" >>"$$IMPORTER_DROP"; \
	printf "ReadWritePaths=$(DATADIR)\n" >>"$$IMPORTER_DROP"; \
	if [ "$(strip $(DYNAMIC_USER))" = "no" ]; then printf "DynamicUser=no\n" >>"$$IMPORTER_DROP"; fi; \
	if [ -n "$(strip $(RUN_USER))" ]; then printf "User=$(RUN_USER)\n" >>"$$IMPORTER_DROP"; fi; \
	if [ -n "$(strip $(RUN_GROUP))" ]; then printf "Group=$(RUN_GROUP)\n" >>"$$IMPORTER_DROP"; fi; \
	if [ -n "$(strip $(SUPP_GROUPS))" ]; then printf "SupplementaryGroups=$(SUPP_GROUPS)\n" >>"$$IMPORTER_DROP"; fi; \
	echo "Wrote $$IMPORTER_DROP";

systemd-enable:
	systemctl daemon-reload
	systemctl enable --now logtool-server
	systemctl enable --now logtool-importer.timer

nginx-install:
	install -Dm644 deploy/nginx/logtool.conf /etc/nginx/conf.d/logtool.conf
	@echo "Reload nginx: systemctl reload nginx"

clean:
	rm -rf ./bin
