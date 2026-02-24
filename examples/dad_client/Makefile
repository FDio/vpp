# Makefile pour l'exemple client DAD

# Chemin vers VPP (ajuster si nécessaire)
VPP_DIR ?= ../..
VPP_INSTALL ?= $(VPP_DIR)/build-root/install-vpp-native

# Compilateur
CC = gcc

# Flags de compilation
CFLAGS = -Wall -Wextra -O2 -g
CFLAGS += -I$(VPP_INSTALL)/vpp/include

# Flags de linkage
LDFLAGS = -L$(VPP_INSTALL)/vpp/lib/x86_64-linux-gnu
LDFLAGS += -lvapiclient -lvppinfra -lpthread

# Cible principale
TARGET = dad_client

# Sources
SRCS = dad_client.c
OBJS = $(SRCS:.c=.o)

# Règle par défaut
all: $(TARGET)

# Compilation du programme
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "✓ Build réussi : $(TARGET)"

# Compilation des fichiers objets
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "✓ Nettoyé"

# Exécution
run: $(TARGET)
	@echo "Lancement de $(TARGET)..."
	@echo "Note: VPP doit être en cours d'exécution"
	@echo ""
	LD_LIBRARY_PATH=$(VPP_INSTALL)/vpp/lib/x86_64-linux-gnu ./$(TARGET)

# Aide
help:
	@echo "Makefile pour l'exemple client DAD IPv6"
	@echo ""
	@echo "Cibles disponibles:"
	@echo "  make          - Compiler le programme"
	@echo "  make run      - Compiler et exécuter"
	@echo "  make clean    - Nettoyer les fichiers compilés"
	@echo "  make help     - Afficher cette aide"

.PHONY: all clean run help
