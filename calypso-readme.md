# Development Notes

## JWT Authentication with q DNS Tool

Send JWT tokens in DNS queries via EDNS OPT records (option code 65001).

### Basic Usage

```bash
./q A --jwt --token "<JWT_TOKEN>" example.com @server

# Over UDP
./q A --jwt --token "<token>" example.com @127.0.0.1:1053

# Over DoT (DNS-over-TLS)
./q A --jwt --token "<token>" example.com @tls://localhost:853

# Over DoH (DNS-over-HTTPS)
./q A --jwt --token "<token>" example.com @https://127.0.0.1:443/dns-query

# With verbose output (shows EDNS0 option details)
./q A --jwt --token "<token>" --verbose example.com @server
```

### Expected Behavior

- **Valid JWT**: Query succeeds (NOERROR)
- **Invalid JWT**: Server returns REFUSED status
- **Missing --token flag**: Error - "--token is required for JWT queries"

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
- JWT stored as raw bytes in EDNS0 OPT record
- CoreDNS must have the public key that corresponds to the private key used to sign the JWT

## Encrypted DNS Records

The tool supports decrypting DNS records encrypted with WKD-IBE or Calypso. The encrypted records are stored as TXT records on the server, but when querying with decryption keys, you can request any record type (A, AAAA, etc.) and `q` will automatically fetch and decrypt the TXT record.

### WKD-IBE Decryption

WKD-IBE (Wildcard Key-Derived Identity-Based Encryption) allows identity-based decryption using hierarchical domain patterns.

**Setup and query:**
```bash
# Generate WKD-IBE parameters and identity key
make setup-wkdibe

# Query A record with automatic decryption
./q A verify.example.com --wkdibe \
  --params=verify_wkdibe_params.bin \
  --key=verify_wkdibe_identity.key \
  @localhost:1053

# The tool automatically queries TXT and decrypts to A record
```

**Technical Details:**
- Uses EDNS0 option code 65002
- Encrypted payload format: binary (IV + AES ciphertext + IBE ciphertext)
- TXT record format: `02:<base64-encoded-payload>`

### Calypso Decryption

Calypso provides searchable encryption with writer/reader key separation.

**Setup and query:**
```bash
# Generate Calypso parameters and writer key
make setup-calypso

# Query A record with automatic decryption
./q A verify.example.com --calypso \
  --params=verify_calypso_params.bin \
  --key=verify_calypso_writer.key \
  @localhost:1053

# The tool automatically:
# 1. Derives the searchtag from the domain name and key
# 2. Queries TXT with searchtag in EDNS0 option
# 3. Decrypts and returns the A record
```

**Technical Details:**
- Uses EDNS0 option code 65003
- Searchtag automatically derived from the **query domain name** using the **loaded key's cryptographic parameters**
  - If querying the exact domain the key is for → uses key's pre-computed searchtag
  - If querying a subdomain matching the key's pattern → derives new searchtag for that specific domain
- Searchtag sent as EDNS0 payload (auto-generated, not user-provided)
- Encrypted payload format: binary (IV + AES ciphertext + Calypso ciphertext)
- TXT record format: `03:<base64-encoded-payload>`

### Verification

Run encryption tests (requires CoreDNS on localhost:1053 with encrypted records):
```bash
make verify-all      # Test all encryption schemes
make verify-wkdibe   # Test WKD-IBE only
make verify-calypso  # Test Calypso only
```

## Performance Measurement

The tool now provides granular timing breakdowns to measure cryptographic overhead separately from DNS network latency.

### Timing Breakdown

When using encrypted approaches (WKD-IBE or Calypso), the `--stats` flag shows three separate timing metrics:

```bash
./q A verify.example.com --calypso \
  --params=verify_calypso_params.bin \
  --key=verify_calypso_writer.key \
  --stats \
  @localhost:1053
```

**Example output:**
```
Stats:
Received 45 B from localhost:1053 in 4.523ms (15:04:05 01-02-2025 UTC)
  ├─ Query prep:  1.234ms
  ├─ DNS network: 2.156ms
  └─ Decryption:  1.133ms
```

### Timing Metrics

- **Query prep**: Request-side cryptographic overhead
  - Calypso: Searchtag generation and key derivation
  - WKD-IBE: Negligible (no query-side crypto)

- **DNS network**: Pure DNS protocol latency (transport overhead only, no crypto)

- **Response crypto**: Response-side cryptographic overhead
  - WKD-IBE: HIBE decryption + AES-CTR decryption
  - Calypso: Message deserialization + HIBE decryption + AES-CTR + BLS signature verification

### Export for Analysis

Use JSON/YAML output formats to export timing data for statistical analysis:

```bash
./q A verify.example.com --calypso \
  --params=verify_calypso_params.bin \
  --key=verify_calypso_writer.key \
  --format=json \
  @localhost:1053
```

The output includes all three timing fields (`QueryCryptoTime`, `DNSTime`, `ResponseCryptoTime`) for programmatic analysis in other tools.