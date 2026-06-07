CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE $(shell pkg-config --cflags gtk+-3.0)
LIBS = $(shell pkg-config --libs gtk+-3.0) -lpthread

SRC_DIR = src
OBJ_DIR = obj
BIN = forensic-tool

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/forensics.c
OBJS = $(OBJ_DIR)/main.o $(OBJ_DIR)/forensics.o

# Installation paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
APPDIR = /usr/share/applications
ICONDIR = /usr/share/icons/hicolor/scalable/apps
PIXMAPDIR = /usr/share/pixmaps

.PHONY: all clean install uninstall

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN)

install: $(BIN)
	@echo "Installing binary to $(BINDIR)..."
	install -D -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

	@echo "Installing application shortcut..."
	install -D -m 644 forensic-tool.desktop $(DESTDIR)$(APPDIR)/forensic-tool.desktop

	@echo "Installing icons..."
	install -D -m 644 resources/forensic-tool.png $(DESTDIR)$(ICONDIR)/forensic-tool.png
	install -D -m 644 resources/forensic-tool.png $(DESTDIR)$(PIXMAPDIR)/forensic-tool.png

	@echo "Updating system databases..."
	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
	-update-desktop-database /usr/share/applications || true
	@echo "Installation complete!"

uninstall:
	@echo "Uninstalling binary..."
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

	@echo "Uninstalling application shortcut..."
	rm -f $(DESTDIR)$(APPDIR)/forensic-tool.desktop

	@echo "Uninstalling icons..."
	rm -f $(DESTDIR)$(ICONDIR)/forensic-tool.png
	rm -f $(DESTDIR)$(PIXMAPDIR)/forensic-tool.png

	@echo "Updating system databases..."
	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
	-update-desktop-database /usr/share/applications || true
	@echo "Uninstallation complete!"
