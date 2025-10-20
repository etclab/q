.PHONY: build test vet clean clean-all clean-verify setup-wkdibe setup-calypso verify-wkdibe verify-calypso verify-all help

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
verify-wkdibe: build setup-wkdibe
	@echo "=== Verifying WKD-IBE Decryption ==="
	@echo "1. Query without key (should show encrypted TXT):"
	@./q TXT verify.example.com @localhost:1053 || true
	@echo ""
	@echo "2. Query A record with WKD-IBE decryption (should show decrypted A record):"
	@./q A verify.example.com --wkdibe --params=verify_wkdibe_params.bin --key=verify_wkdibe_identity.key @localhost:1053
	@echo "✓ WKD-IBE verification complete"
	@$(MAKE) clean-verify

verify-calypso: build setup-calypso
	@echo "=== Verifying Calypso Decryption ==="
	@echo "1. Query without key (should show encrypted TXT):"
	@./q TXT verify.example.com @localhost:1053 || true
	@echo ""
	@echo "2. Query A record with Calypso decryption (should show decrypted A record):"
	@./q A verify.example.com --calypso --searchtag=test --params=verify_calypso_params.bin --key=verify_calypso_writer.key @localhost:1053
	@echo "✓ Calypso verification complete"
	@$(MAKE) clean-verify

verify-all: verify-wkdibe verify-calypso
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
	@echo "  setup-wkdibe    - Generate WKD-IBE test keys (requires etcd-client)"
	@echo "  setup-calypso   - Generate Calypso test keys (requires etcd-client)"
	@echo ""
	@echo "Verification (requires CoreDNS on localhost:1053 with encrypted records):"
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
	@echo "  WKDIBE_PARAMS_FILE  - Path to WKD-IBE parameters"
	@echo "  WKDIBE_KEY_FILE     - Path to WKD-IBE private key"
	@echo "  CALYPSO_PARAMS_FILE - Path to Calypso parameters"
	@echo "  CALYPSO_KEY_FILE    - Path to Calypso reader/writer key"