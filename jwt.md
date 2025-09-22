# Development Notes

## JWT Authentication with q DNS Tool

Send JWT tokens in DNS queries via EDNS OPT records (option code 65001).

### Basic Usage

```bash
./q A --jwt="<JWT_TOKEN>" example.com @server
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