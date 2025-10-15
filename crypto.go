package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/calypso"
	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
	log "github.com/sirupsen/logrus"
)

// CryptoConfig holds encryption keys and parameters
type CryptoConfig struct {
	RSAPrivateKey      *rsa.PrivateKey
	WKDIBEPublicParams *akn07.PublicParams
	WKDIBEPrivateKey   *akn07.PrivateKey
	CalypsoPublicParams *akn07.PublicParams
	CalypsoPrivateKey  *calypso.PrivateKey
}

// LoadCryptoConfig loads encryption keys from environment variables
func LoadCryptoConfig() (*CryptoConfig, error) {
	cfg := &CryptoConfig{}

	// Load RSA private key if configured
	if rsaKeyPath := os.Getenv("RSA_KEY_FILE"); rsaKeyPath != "" {
		log.Debugf("Loading RSA key from %s", rsaKeyPath)
		key, err := loadRSAPrivateKey(rsaKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading RSA key: %w", err)
		}
		cfg.RSAPrivateKey = key
		log.Debug("RSA key loaded successfully")
	}

	// Load WKD-IBE keys if configured
	wkdibeParamsPath := os.Getenv("WKDIBE_PARAMS_FILE")
	wkdibeKeyPath := os.Getenv("WKDIBE_KEY_FILE")
	if wkdibeParamsPath != "" && wkdibeKeyPath != "" {
		log.Debugf("Loading WKD-IBE params from %s and key from %s", wkdibeParamsPath, wkdibeKeyPath)
		params, key, err := loadWKDIBEKeys(wkdibeParamsPath, wkdibeKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading WKD-IBE keys: %w", err)
		}
		cfg.WKDIBEPublicParams = params
		cfg.WKDIBEPrivateKey = key
		log.Debug("WKD-IBE keys loaded successfully")
	}

	// Load Calypso keys if configured
	calypsoParamsPath := os.Getenv("CALYPSO_PARAMS_FILE")
	calypsoKeyPath := os.Getenv("CALYPSO_KEY_FILE")
	if calypsoParamsPath != "" && calypsoKeyPath != "" {
		log.Debugf("Loading Calypso params from %s and key from %s", calypsoParamsPath, calypsoKeyPath)
		params, key, err := loadCalypsoKeys(calypsoParamsPath, calypsoKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading Calypso keys: %w", err)
		}
		cfg.CalypsoPublicParams = params
		cfg.CalypsoPrivateKey = key
		log.Debug("Calypso keys loaded successfully")
	}

	return cfg, nil
}

// loadRSAPrivateKey loads an RSA private key from a PEM file
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format first
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("not an RSA private key")
	}

	// Fall back to PKCS1 format
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// loadWKDIBEKeys loads WKD-IBE public parameters and private key
func loadWKDIBEKeys(paramsPath, keyPath string) (*akn07.PublicParams, *akn07.PrivateKey, error) {
	// Load public params
	paramsData, err := os.ReadFile(paramsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading params file: %w", err)
	}

	params := &akn07.PublicParams{}
	if err := params.UnmarshalBinary(paramsData); err != nil {
		return nil, nil, fmt.Errorf("deserializing public params: %w", err)
	}

	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key file: %w", err)
	}

	key := &akn07.PrivateKey{}
	if err := key.UnmarshalBinary(keyData); err != nil {
		return nil, nil, fmt.Errorf("deserializing private key: %w", err)
	}

	return params, key, nil
}

// HasAnyKey returns true if any encryption key is configured
func (c *CryptoConfig) HasAnyKey() bool {
	return c.RSAPrivateKey != nil || c.WKDIBEPrivateKey != nil || c.CalypsoPrivateKey != nil
}

// CryptoType represents the encryption type
type CryptoType byte

const (
	CryptoTypeRSA     CryptoType = 0x01
	CryptoTypeWKDIBE  CryptoType = 0x02
	CryptoTypeCalypso CryptoType = 0x03
)

// ParsedTXTRecord represents a parsed encrypted TXT record
type ParsedTXTRecord struct {
	Type    CryptoType
	Payload []byte
}

// ParseTXTRecord parses a TXT record in TYPE:BASE64 format
// Format: "01:YmFzZTY0ZW5jcnlwdGVk" where 01 is hex crypto type
func ParseTXTRecord(txtData string) (*ParsedTXTRecord, error) {
	// Split on colon
	parts := strings.SplitN(txtData, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid TXT format: expected TYPE:BASE64")
	}

	// Parse type (hex string like "01", "02", "03")
	typeNum, err := strconv.ParseUint(parts[0], 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid crypto type: %w", err)
	}

	cryptoType := CryptoType(typeNum)
	if cryptoType != CryptoTypeRSA && cryptoType != CryptoTypeWKDIBE && cryptoType != CryptoTypeCalypso {
		return nil, fmt.Errorf("unknown crypto type: 0x%02x", cryptoType)
	}

	// Decode base64 payload
	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}

	log.Debugf("Parsed TXT record: type=0x%02x, payload_len=%d", cryptoType, len(payload))

	return &ParsedTXTRecord{
		Type:    cryptoType,
		Payload: payload,
	}, nil
}

// DecryptResponse decrypts the encrypted payload and returns the IP address
func (c *CryptoConfig) DecryptResponse(parsed *ParsedTXTRecord) (string, error) {
	switch parsed.Type {
	case CryptoTypeRSA:
		return c.decryptRSA(parsed.Payload)
	case CryptoTypeWKDIBE:
		return c.decryptWKDIBE(parsed.Payload)
	case CryptoTypeCalypso:
		return c.decryptCalypso(parsed.Payload)
	default:
		return "", fmt.Errorf("unknown crypto type: 0x%02x", parsed.Type)
	}
}

// decryptRSA decrypts RSA-encrypted data and extracts the IP address
func (c *CryptoConfig) decryptRSA(ciphertext []byte) (string, error) {
	if c.RSAPrivateKey == nil {
		return "", fmt.Errorf("RSA key not configured (set RSA_KEY_FILE)")
	}

	log.Debugf("Decrypting RSA ciphertext (len=%d)", len(ciphertext))

	// Decrypt using OAEP with SHA-256 (modern secure padding)
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.RSAPrivateKey, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("RSA decryption failed: %w", err)
	}

	log.Debugf("Decrypted plaintext: %s", string(plaintext))

	// Parse standard JSON format: {"host": "...", "ttl": ...}
	var record struct {
		Host string `json:"host"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return "", fmt.Errorf("failed to parse JSON record: %w", err)
	}

	if record.Host == "" {
		return "", fmt.Errorf("JSON record missing 'host' field, got: %s", string(plaintext))
	}

	return record.Host, nil
}

// decryptWKDIBE decrypts WKD-IBE-encrypted data and extracts the IP address
// Binary format: [version|IV_len|IV|AES_ct_len|AES_ct|WKDIBE_ct]
func (c *CryptoConfig) decryptWKDIBE(ciphertext []byte) (string, error) {
	if c.WKDIBEPublicParams == nil || c.WKDIBEPrivateKey == nil {
		return "", fmt.Errorf("WKD-IBE keys not configured (set WKDIBE_PARAMS_FILE and WKDIBE_KEY_FILE)")
	}

	log.Debugf("Decrypting WKD-IBE ciphertext (len=%d)", len(ciphertext))

	// Minimum size check: version(1) + IV_len(2) + IV(16) + AES_ct_len(4) + at least some data
	if len(ciphertext) < 1+2+16+4+1 {
		return "", fmt.Errorf("ciphertext too short (len=%d)", len(ciphertext))
	}

	offset := 0

	// 1. Parse version
	version := ciphertext[offset]
	offset++
	if version != 1 {
		return "", fmt.Errorf("unsupported ciphertext version: %d", version)
	}

	// 2. Parse IV length and IV
	ivLen := binary.BigEndian.Uint16(ciphertext[offset:])
	offset += 2
	if offset+int(ivLen) > len(ciphertext) {
		return "", fmt.Errorf("invalid IV length: %d", ivLen)
	}
	iv := ciphertext[offset : offset+int(ivLen)]
	offset += int(ivLen)
	log.Debugf("WKD-IBE IV length: %d", ivLen)

	// 3. Parse AES ciphertext length and AES ciphertext
	if offset+4 > len(ciphertext) {
		return "", fmt.Errorf("ciphertext too short for AES length")
	}
	aesCtLen := binary.BigEndian.Uint32(ciphertext[offset:])
	offset += 4
	if offset+int(aesCtLen) > len(ciphertext) {
		return "", fmt.Errorf("invalid AES ciphertext length: %d", aesCtLen)
	}
	aesCt := ciphertext[offset : offset+int(aesCtLen)]
	offset += int(aesCtLen)
	log.Debugf("WKD-IBE AES ciphertext length: %d", aesCtLen)

	// 4. Parse WKD-IBE ciphertext
	hibeCtBytes := ciphertext[offset:]
	log.Debugf("WKD-IBE ciphertext length: %d", len(hibeCtBytes))

	hibeCt := &akn07.Ciphertext{}
	if err := hibeCt.UnmarshalBinary(hibeCtBytes); err != nil {
		return "", fmt.Errorf("WKD-IBE ciphertext deserialization failed: %w", err)
	}

	// 5. WKD-IBE decrypt to get Gt
	m := akn07.Decrypt(c.WKDIBEPublicParams, c.WKDIBEPrivateKey, hibeCt)
	log.Debug("WKD-IBE decryption successful, deriving AES key")

	// 6. Derive AES key from Gt
	aesKey := blspairing.KdfGtToAes256(m)

	// 7. AES-CTR decrypt
	plaintext, err := aesx.DecryptCTR(aesKey, iv, aesCt)
	if err != nil {
		return "", fmt.Errorf("AES decryption failed: %w", err)
	}

	log.Debugf("Decrypted plaintext: %s", string(plaintext))

	// Parse standard JSON format: {"host": "...", "ttl": ...}
	var record struct {
		Host string `json:"host"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return "", fmt.Errorf("failed to parse JSON record: %w", err)
	}

	if record.Host == "" {
		return "", fmt.Errorf("JSON record missing 'host' field, got: %s", string(plaintext))
	}

	return record.Host, nil
}

// loadCalypsoKeys loads Calypso public parameters and private key
func loadCalypsoKeys(paramsPath, keyPath string) (*akn07.PublicParams, *calypso.PrivateKey, error) {
	// Load public params (same as WKD-IBE)
	paramsData, err := os.ReadFile(paramsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading params file: %w", err)
	}

	params := &akn07.PublicParams{}
	if err := params.UnmarshalBinary(paramsData); err != nil {
		return nil, nil, fmt.Errorf("deserializing public params: %w", err)
	}

	// Load Calypso private key (gob encoded)
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key file: %w", err)
	}

	key := &calypso.PrivateKey{}
	buf := bytes.NewBuffer(keyData)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(key); err != nil {
		return nil, nil, fmt.Errorf("deserializing private key: %w", err)
	}

	return params, key, nil
}

// DeserializeSignature deserializes bytes to an akn07.Signature
func DeserializeSignature(data []byte) (*akn07.Signature, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("signature data too short")
	}

	offset := 0
	s0Len := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(s0Len) > len(data) {
		return nil, fmt.Errorf("invalid S0 length")
	}

	s0 := new(bls.G1)
	if err := s0.SetBytes(data[offset : offset+int(s0Len)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize S0: %w", err)
	}
	offset += int(s0Len)

	if offset+4 > len(data) {
		return nil, fmt.Errorf("signature data too short for S1 length")
	}
	s1Len := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(s1Len) != len(data) {
		return nil, fmt.Errorf("invalid S1 length")
	}

	s1 := new(bls.G2)
	if err := s1.SetBytes(data[offset : offset+int(s1Len)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize S1: %w", err)
	}

	return &akn07.Signature{S0: s0, S1: s1}, nil
}

// DeserializeMessage deserializes bytes to a Calypso Message
// Format: [version|SearchTag_len|SearchTag|WrappedKey_len|WrappedKey|IV_len|IV|Ciphertext_len|Ciphertext|Signature_len|Signature]
func DeserializeMessage(data []byte) (*calypso.Message, error) {
	if len(data) < 1+2+4+2+4+4 {
		return nil, fmt.Errorf("message data too short")
	}

	offset := 0

	// Version
	version := data[offset]
	offset++
	if version != 1 {
		return nil, fmt.Errorf("unsupported message version: %d", version)
	}

	// SearchTag
	searchTagLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(searchTagLen) > len(data) {
		return nil, fmt.Errorf("invalid SearchTag length")
	}
	searchTag := string(data[offset : offset+int(searchTagLen)])
	offset += int(searchTagLen)

	// WrappedKey
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for WrappedKey length")
	}
	wrappedKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(wrappedKeyLen) > len(data) {
		return nil, fmt.Errorf("invalid WrappedKey length")
	}
	wrappedKey := &akn07.Ciphertext{}
	if err := wrappedKey.UnmarshalBinary(data[offset : offset+int(wrappedKeyLen)]); err != nil {
		return nil, fmt.Errorf("failed to deserialize WrappedKey: %w", err)
	}
	offset += int(wrappedKeyLen)

	// IV
	if offset+2 > len(data) {
		return nil, fmt.Errorf("message data too short for IV length")
	}
	ivLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(ivLen) > len(data) {
		return nil, fmt.Errorf("invalid IV length")
	}
	iv := data[offset : offset+int(ivLen)]
	offset += int(ivLen)

	// Ciphertext
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for Ciphertext length")
	}
	ciphertextLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(ciphertextLen) > len(data) {
		return nil, fmt.Errorf("invalid Ciphertext length")
	}
	ciphertext := data[offset : offset+int(ciphertextLen)]
	offset += int(ciphertextLen)

	// Signature
	if offset+4 > len(data) {
		return nil, fmt.Errorf("message data too short for Signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(sigLen) != len(data) {
		return nil, fmt.Errorf("invalid Signature length")
	}
	signature, err := DeserializeSignature(data[offset : offset+int(sigLen)])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Signature: %w", err)
	}

	return &calypso.Message{
		SearchTag:  searchTag,
		WrappedKey: wrappedKey,
		IV:         iv,
		Ciphertext: ciphertext,
		Signature:  signature,
	}, nil
}

// decryptCalypso decrypts Calypso-encrypted data and extracts the IP address
// Binary format: [version|SearchTag_len|SearchTag|WrappedKey_len|WrappedKey|IV_len|IV|Ciphertext_len|Ciphertext|Signature_len|Signature]
func (c *CryptoConfig) decryptCalypso(ciphertext []byte) (string, error) {
	if c.CalypsoPublicParams == nil || c.CalypsoPrivateKey == nil {
		return "", fmt.Errorf("Calypso keys not configured (set CALYPSO_PARAMS_FILE and CALYPSO_KEY_FILE)")
	}

	log.Debugf("Decrypting Calypso ciphertext (len=%d)", len(ciphertext))

	// Deserialize bytes to Message
	message, err := DeserializeMessage(ciphertext)
	if err != nil {
		return "", fmt.Errorf("message deserialization failed: %w", err)
	}

	log.Debugf("Calypso message: SearchTag=%s", message.SearchTag)

	// Decrypt and verify using Calypso (uses key's embedded domain for verification)
	plaintext, err := c.CalypsoPrivateKey.DecryptAndVerify(c.CalypsoPrivateKey.DomainName, message)
	if err != nil {
		return "", fmt.Errorf("DecryptAndVerify failed (signature verification may have failed): %w", err)
	}

	log.Debugf("Decrypted plaintext: %s", string(plaintext))

	// Parse standard JSON format: {"host": "...", "ttl": ...}
	var record struct {
		Host string `json:"host"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return "", fmt.Errorf("failed to parse JSON record: %w", err)
	}

	if record.Host == "" {
		return "", fmt.Errorf("JSON record missing 'host' field, got: %s", string(plaintext))
	}

	return record.Host, nil
}
