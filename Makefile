.PHONY: build test vet clean clean-all clean-verify setup-rsa setup-wkdibe setup-calypso verify-rsa verify-wkdibe verify-calypso verify-all help

# Build targets
build:
	go build -o q

test:
	go test -v

vet:
	go vet

# Cleanup targets
clean:
	rm -f q

clean-all:
	rm -f q *.pem *.key *.bin

clean-verify:
	rm -f verify_*.pem verify_*.key verify_*.bin

# Setup targets for generating test keys
setup-rsa:
	@echo "=== Generating RSA test keys ==="
	openssl genrsa -traditional -out verify_rsa_private.pem 2048 2>/dev/null
	openssl rsa -in verify_rsa_private.pem -pubout -out verify_rsa_public.pem 2>/dev/null
	@echo "RSA keys generated: verify_rsa_public.pem, verify_rsa_private.pem"

setup-wkdibe:
	@echo "=== Setting up WKD-IBE parameters ==="
	@echo "Note: Requires etcd-client tool for key generation"
	@which etcd-client >/dev/null || (echo "Error: etcd-client not found in PATH" && exit 1)
	etcd-client wkdibe setup --max-depth 5 --output verify_wkdibe_params.bin --master-key verify_wkdibe_master.key
	etcd-client wkdibe keygen --params verify_wkdibe_params.bin --master-key verify_wkdibe_master.key \
		--pattern "com,example,verify" --output verify_wkdibe_identity.key
	@echo "WKD-IBE setup complete"

setup-calypso:
	@echo "=== Setting up Calypso parameters ==="
	@echo "Note: Requires etcd-client tool for key generation"
	@which etcd-client >/dev/null || (echo "Error: etcd-client not found in PATH" && exit 1)
	etcd-client calypso setup --max-depth 5 --output verify_calypso_params.bin --authority verify_calypso_authority.bin
	etcd-client calypso keygen --params verify_calypso_params.bin --authority verify_calypso_authority.bin \
		--domain "verify.example.com" --writer --output verify_calypso_writer.key
	@echo "Calypso setup complete"

# Verification targets (requires CoreDNS running on localhost:1053 with encrypted records)
verify-rsa: build setup-rsa
	@echo "=== Verifying RSA Decryption ==="
	@echo "1. Query without key (should show encrypted TXT):"
	@./q TXT verify.example.com @localhost:1053 || true
	@echo ""
	@echo "2. Query with RSA key (should show decrypted A record):"
	@RSA_KEY_FILE=verify_rsa_private.pem ./q TXT verify.example.com @localhost:1053
	@echo "✓ RSA verification complete"
	@$(MAKE) clean-verify

verify-wkdibe: build setup-wkdibe
	@echo "=== Verifying WKD-IBE Decryption ==="
	@echo "1. Query without key (should show encrypted TXT):"
	@./q TXT verify.example.com @localhost:1053 || true
	@echo ""
	@echo "2. Query with WKD-IBE key (should show decrypted A record):"
	@WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key \
		./q TXT verify.example.com @localhost:1053
	@echo "✓ WKD-IBE verification complete"
	@$(MAKE) clean-verify

verify-calypso: build setup-calypso
	@echo "=== Verifying Calypso Decryption ==="
	@echo "1. Query without key (should show encrypted TXT):"
	@./q TXT verify.example.com @localhost:1053 || true
	@echo ""
	@echo "2. Query with Calypso key (should show decrypted A record):"
	@CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_KEY_FILE=verify_calypso_writer.key \
		./q TXT verify.example.com @localhost:1053
	@echo "✓ Calypso verification complete"
	@$(MAKE) clean-verify

verify-all: verify-rsa verify-wkdibe verify-calypso
	@echo ""
	@echo "=========================================="
	@echo "✓ All verification tests passed!"
	@echo "=========================================="

help:
	@echo "Available targets:"
	@echo ""
	@echo "Build & Test:"
	@echo "  build           - Build the q binary"
	@echo "  test            - Run all Go tests"
	@echo "  vet             - Run go vet"
	@echo ""
	@echo "Setup (generate test keys):"
	@echo "  setup-rsa       - Generate RSA test keys"
	@echo "  setup-wkdibe    - Generate WKD-IBE test keys (requires etcd-client)"
	@echo "  setup-calypso   - Generate Calypso test keys (requires etcd-client)"
	@echo ""
	@echo "Verification (requires CoreDNS on localhost:1053 with encrypted records):"
	@echo "  verify-rsa      - Verify RSA decryption"
	@echo "  verify-wkdibe   - Verify WKD-IBE decryption"
	@echo "  verify-calypso  - Verify Calypso decryption"
	@echo "  verify-all      - Run all verification tests"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean           - Remove built binary"
	@echo "  clean-all       - Remove binary and all .pem/.key/.bin files"
	@echo "  clean-verify    - Remove only verification test keys"
	@echo ""
	@echo "Environment Variables:"
	@echo "  RSA_KEY_FILE        - Path to RSA private key"
	@echo "  WKDIBE_PARAMS_FILE  - Path to WKD-IBE parameters"
	@echo "  WKDIBE_KEY_FILE     - Path to WKD-IBE private key"
	@echo "  CALYPSO_PARAMS_FILE - Path to Calypso parameters"
	@echo "  CALYPSO_KEY_FILE    - Path to Calypso reader/writer key"