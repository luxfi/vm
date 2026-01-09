// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantum

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/cache"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	ErrInvalidQuantumSignature   = errors.New("invalid quantum signature")
	ErrInvalidRingtailKey        = errors.New("invalid ringtail key")
	ErrQuantumStampExpired       = errors.New("quantum stamp expired")
	ErrQuantumVerificationFailed = errors.New("quantum verification failed")
	ErrUnsupportedAlgorithm      = errors.New("unsupported quantum algorithm")
)

// Algorithm versions
const (
	AlgorithmMLDSA44 uint32 = 1 // NIST Level 2 (128-bit security)
	AlgorithmMLDSA65 uint32 = 2 // NIST Level 3 (192-bit security)
	AlgorithmMLDSA87 uint32 = 3 // NIST Level 5 (256-bit security)
)

// QuantumSigner handles quantum signature operations using ML-DSA (Dilithium)
type QuantumSigner struct {
	log              log.Logger
	algorithmVersion uint32
	mldsaMode        mldsa.Mode
	stampWindow      time.Duration
	sigCache         *cache.LRU[ids.ID, *QuantumSignature]
	mu               sync.RWMutex
}

// QuantumSignature represents a quantum-resistant signature
type QuantumSignature struct {
	Algorithm    uint32
	Timestamp    time.Time
	PublicKey    []byte
	Signature    []byte
	RingtailKey  []byte
	QuantumStamp []byte
}

// RingtailKey represents a Ringtail key for quantum resistance (using ML-DSA)
type RingtailKey struct {
	Version    uint32
	PublicKey  []byte
	PrivateKey []byte
	Nonce      []byte
	mldsaPriv  *mldsa.PrivateKey
}

// NewQuantumSigner creates a new quantum signer with real ML-DSA
// algorithmVersion: 1=MLDSA44, 2=MLDSA65, 3=MLDSA87
// keySize is ignored (determined by algorithm)
func NewQuantumSigner(log log.Logger, algorithmVersion uint32, keySize int, stampWindow time.Duration, cacheSize int) *QuantumSigner {
	var mode mldsa.Mode
	switch algorithmVersion {
	case AlgorithmMLDSA44:
		mode = mldsa.MLDSA44
	case AlgorithmMLDSA65:
		mode = mldsa.MLDSA65
	case AlgorithmMLDSA87:
		mode = mldsa.MLDSA87
	default:
		mode = mldsa.MLDSA65 // Default to NIST Level 3
		algorithmVersion = AlgorithmMLDSA65
	}

	return &QuantumSigner{
		log:              log,
		algorithmVersion: algorithmVersion,
		mldsaMode:        mode,
		stampWindow:      stampWindow,
		sigCache:         &cache.LRU[ids.ID, *QuantumSignature]{Size: cacheSize},
	}
}

// GenerateRingtailKey generates a new ML-DSA key pair
func (qs *QuantumSigner) GenerateRingtailKey() (*RingtailKey, error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	// Generate real ML-DSA key pair using circl
	mldsaPriv, err := mldsa.GenerateKey(rand.Reader, qs.mldsaMode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA key: %w", err)
	}

	// Generate nonce for quantum stamp
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &RingtailKey{
		Version:    qs.algorithmVersion,
		PublicKey:  mldsaPriv.PublicKey.Bytes(),
		PrivateKey: mldsaPriv.Bytes(),
		Nonce:      nonce,
		mldsaPriv:  mldsaPriv,
	}, nil
}

// Sign creates a quantum signature for the given message using ML-DSA
func (qs *QuantumSigner) Sign(message []byte, key *RingtailKey) (*QuantumSignature, error) {
	if key == nil {
		return nil, ErrInvalidRingtailKey
	}

	// Restore ML-DSA key if not cached
	var mldsaPriv *mldsa.PrivateKey
	if key.mldsaPriv != nil {
		mldsaPriv = key.mldsaPriv
	} else {
		var err error
		mldsaPriv, err = mldsa.PrivateKeyFromBytes(qs.mldsaMode, key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to restore ML-DSA key: %w", err)
		}
	}

	// Generate quantum stamp
	stamp, err := qs.generateQuantumStamp(message, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quantum stamp: %w", err)
	}

	// Create message to sign: message || stamp
	data := make([]byte, len(message)+len(stamp))
	copy(data, message)
	copy(data[len(message):], stamp)

	// Sign with ML-DSA (real post-quantum signature!)
	signature, err := mldsaPriv.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}

	sig := &QuantumSignature{
		Algorithm:    qs.algorithmVersion,
		Timestamp:    time.Now(),
		PublicKey:    key.PublicKey,
		Signature:    signature,
		RingtailKey:  key.PublicKey,
		QuantumStamp: stamp,
	}

	// Cache the signature
	sigID := qs.computeSignatureID(sig)
	qs.sigCache.Put(sigID, sig)

	return sig, nil
}

// Verify verifies a quantum signature using ML-DSA
func (qs *QuantumSigner) Verify(message []byte, sig *QuantumSignature) error {
	if sig == nil {
		return ErrInvalidQuantumSignature
	}

	// Verify algorithm version
	if sig.Algorithm != qs.algorithmVersion {
		return ErrUnsupportedAlgorithm
	}

	// Verify timestamp
	if time.Since(sig.Timestamp) > qs.stampWindow {
		return ErrQuantumStampExpired
	}

	// Verify quantum stamp exists
	if err := qs.verifyQuantumStamp(message, sig); err != nil {
		return fmt.Errorf("quantum stamp verification failed: %w", err)
	}

	// Restore public key
	pubKey, err := mldsa.PublicKeyFromBytes(sig.PublicKey, qs.mldsaMode)
	if err != nil {
		return fmt.Errorf("invalid ML-DSA public key: %w", err)
	}

	// Recreate the signed message: message || stamp
	data := make([]byte, len(message)+len(sig.QuantumStamp))
	copy(data, message)
	copy(data[len(message):], sig.QuantumStamp)

	// Verify with ML-DSA (real post-quantum verification!)
	if !pubKey.VerifySignature(data, sig.Signature) {
		return ErrQuantumVerificationFailed
	}

	return nil
}

// generateQuantumStamp generates a quantum stamp for message authentication
func (qs *QuantumSigner) generateQuantumStamp(message []byte, key *RingtailKey) ([]byte, error) {
	// Combine message, key nonce, and timestamp
	timestamp := time.Now().UnixNano()
	data := make([]byte, len(message)+len(key.Nonce)+8)
	copy(data, message)
	copy(data[len(message):], key.Nonce)
	binary.BigEndian.PutUint64(data[len(message)+len(key.Nonce):], uint64(timestamp))

	// Generate quantum stamp using SHA-512
	hash := sha512.Sum512(data)

	// Add quantum noise
	noise := make([]byte, 32)
	if _, err := rand.Read(noise); err != nil {
		return nil, err
	}

	stamp := make([]byte, len(hash)+len(noise))
	copy(stamp, hash[:])
	copy(stamp[len(hash):], noise)

	return stamp, nil
}

// verifyQuantumStamp verifies a quantum stamp
func (qs *QuantumSigner) verifyQuantumStamp(message []byte, sig *QuantumSignature) error {
	if len(sig.QuantumStamp) < 64 {
		return ErrInvalidQuantumSignature
	}
	// Quantum stamp is verified through ML-DSA signature
	// The stamp is bound to the message in the signature
	return nil
}

// computeSignatureID computes a unique ID for a signature
func (qs *QuantumSigner) computeSignatureID(sig *QuantumSignature) ids.ID {
	data := make([]byte, 0, len(sig.Signature)+len(sig.PublicKey)+8)
	data = append(data, sig.Signature...)
	data = append(data, sig.PublicKey...)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(sig.Timestamp.Unix()))
	data = append(data, timestampBytes...)

	id, _ := ids.ToID(data)
	return id
}

// ParallelVerify verifies multiple signatures in parallel
func (qs *QuantumSigner) ParallelVerify(messages [][]byte, signatures []*QuantumSignature) error {
	if len(messages) != len(signatures) {
		return errors.New("message and signature count mismatch")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(messages))

	for i := range messages {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := qs.Verify(messages[idx], signatures[idx]); err != nil {
				errChan <- fmt.Errorf("signature %d verification failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// GetSignatureSize returns the signature size for the current algorithm
func (qs *QuantumSigner) GetSignatureSize() int {
	return mldsa.GetSignatureSize(qs.mldsaMode)
}

// GetPublicKeySize returns the public key size for the current algorithm
func (qs *QuantumSigner) GetPublicKeySize() int {
	return mldsa.GetPublicKeySize(qs.mldsaMode)
}

// GetMode returns the ML-DSA mode being used
func (qs *QuantumSigner) GetMode() mldsa.Mode {
	return qs.mldsaMode
}
