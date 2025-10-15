# Development Notes

## JWT Authentication with q DNS Tool

Send JWT tokens in DNS queries via EDNS OPT records (option code 65001).

### Basic Usage

```bash
./q A --jwt="<JWT_TOKEN>" example.com @server

# Over UDP
./q A --jwt="<token>" --verbose --opt example.com @127.0.0.1:1053

# Over DoT (DNS-over-TLS)
./q A --jwt="<token>" --verbose --opt example.com @localhost:853

# Over DoH (DNS-over-HTTPS)
./q A --jwt="<token>" --verbose --opt example.com @https://127.0.0.1:443/dns-query
```

### Debug Mode

```bash
./q A --jwt="<TOKEN>" --verbose example.com @server
```

Shows: `"Adding JWT token to EDNS0 OPT record (code 65001)"`

### Expected Behavior

- **Valid JWT**: Query succeeds (NOERROR)
- **Invalid/Missing JWT**: Server returns REFUSED status
- **Empty --jwt=""**: No EDNS option added

### JWT Requirements (CoreDNS jwt_edns plugin)

```json
{
  "client_id": "client-1",
  "permissions": ["query"],
  "allowed_zones": ["example.com"],
  "iss": "issuer",
  "exp": 1758648690
}
```

### Technical Details

- Uses EDNS0 option code 65001 (private range)
- Compatible with CoreDNS `jwt_edns` plugin
- JWT stored as raw bytes in DNS query
- CoreDNS has to have access to the public key whose private key generated the JWT token

## Encrypted DNS Records

The tool supports decrypting DNS records encrypted with RSA, WKD-IBE, or Calypso. Queries without keys show encrypted TXT records; with keys, decrypted content is returned.

### RSA Decryption

Setup and query:
```bash
# Generate RSA keys
make setup-rsa

# Query with RSA private key
RSA_KEY_FILE=verify_rsa_private.pem ./q TXT verify.example.com @localhost:1053
```

### WKD-IBE Decryption

Requires `etcd-client` tool for key generation.

Setup and query:
```bash
# Generate WKD-IBE parameters and identity key (requires etcd-client)
make setup-wkdibe

# Query with WKD-IBE key
WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key \
  ./q TXT verify.example.com @localhost:1053
```

### Calypso Decryption

Requires `etcd-client` tool for key generation.

Setup and query:
```bash
# Generate Calypso parameters and writer key (requires etcd-client)
make setup-calypso

# Query with Calypso key
CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_KEY_FILE=verify_calypso_writer.key \
  ./q TXT verify.example.com @localhost:1053
```

### Verification

Run all encryption tests (requires CoreDNS on localhost:1053 with encrypted records):
```bash
make verify-all      # Test all three encryption schemes
make verify-rsa      # Test RSA only
make verify-wkdibe   # Test WKD-IBE only
make verify-calypso  # Test Calypso only
```