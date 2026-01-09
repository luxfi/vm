// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package qvm

import (
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/vm/vms/quantumvm/config"
	"github.com/luxfi/vm/vms/quantumvm/quantum"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	require := require.New(t)

	// Create factory with default config
	factory := &Factory{
		Config: config.DefaultConfig(),
	}

	// Create VM instance
	logger := log.NoLog{}
	vm, err := factory.New(logger)
	require.NoError(err)
	require.NotNil(vm)

	// Verify it's a QVM instance
	qvm, ok := vm.(*VM)
	require.True(ok)
	require.NotNil(qvm)
	require.Equal(config.DefaultConfig().TxFee, qvm.Config.TxFee)
}

func TestQuantumSigner(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with ML-DSA-44 (NIST Level 2)
	// algorithmVersion: 1=MLDSA44, 2=MLDSA65, 3=MLDSA87
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		quantum.AlgorithmMLDSA44, // ML-DSA-44 (NIST Level 2)
		0,                        // key size ignored (determined by algorithm)
		30*time.Second,           // stamp window
		100,                      // cache size
	)
	require.NotNil(signer)

	// Generate Ringtail key (now using real ML-DSA)
	key, err := signer.GenerateRingtailKey()
	require.NoError(err)
	require.NotNil(key)
	// ML-DSA-44 key sizes: public=1312, private=2560
	require.Equal(signer.GetPublicKeySize(), len(key.PublicKey))
	require.True(len(key.PrivateKey) > 0)

	// Sign a message
	message := []byte("test message for quantum signature")
	sig, err := signer.Sign(message, key)
	require.NoError(err)
	require.NotNil(sig)

	// Verify the signature
	err = signer.Verify(message, sig)
	require.NoError(err)

	// Verify with wrong message should fail
	wrongMessage := []byte("wrong message")
	err = signer.Verify(wrongMessage, sig)
	require.Error(err)
}

func TestParallelVerification(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with ML-DSA-44
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		quantum.AlgorithmMLDSA44, // ML-DSA-44 (NIST Level 2)
		0,                        // key size ignored
		30*time.Second,           // stamp window
		100,                      // cache size
	)

	// Generate multiple keys and signatures
	numSigs := 10
	messages := make([][]byte, numSigs)
	signatures := make([]*quantum.QuantumSignature, numSigs)

	for i := 0; i < numSigs; i++ {
		key, err := signer.GenerateRingtailKey()
		require.NoError(err)

		message := []byte(string(rune('a'+i)) + " test message")
		messages[i] = message

		sig, err := signer.Sign(message, key)
		require.NoError(err)
		signatures[i] = sig
	}

	// Verify all signatures in parallel
	err := signer.ParallelVerify(messages, signatures)
	require.NoError(err)

	// Corrupt one signature and verify should fail
	signatures[5].Signature[0] ^= 0xFF
	err = signer.ParallelVerify(messages, signatures)
	require.Error(err)
}

func TestConfigValidation(t *testing.T) {
	require := require.New(t)

	// Test default config
	cfg := config.DefaultConfig()
	require.NoError(cfg.Validate())

	// Test config with invalid values gets corrected
	cfg.MaxParallelTxs = -1
	cfg.ParallelBatchSize = 0
	cfg.QuantumSigCacheSize = -100
	cfg.RingtailKeySize = 256

	require.NoError(cfg.Validate())

	// Values should be corrected
	require.Greater(cfg.MaxParallelTxs, 0)
	require.Greater(cfg.ParallelBatchSize, 0)
	require.Greater(cfg.QuantumSigCacheSize, 0)
	require.GreaterOrEqual(cfg.RingtailKeySize, 1024)
}

func TestQuantumStampExpiration(t *testing.T) {
	require := require.New(t)

	// Create quantum signer with short stamp window
	logger := log.NoLog{}
	signer := quantum.NewQuantumSigner(
		logger,
		1,                    // algorithm version
		1024,                 // key size
		100*time.Millisecond, // very short stamp window
		100,                  // cache size
	)

	// Generate key and sign message
	key, err := signer.GenerateRingtailKey()
	require.NoError(err)

	message := []byte("test message")
	sig, err := signer.Sign(message, key)
	require.NoError(err)

	// Immediate verification should work
	err = signer.Verify(message, sig)
	require.NoError(err)

	// Wait for stamp to expire
	time.Sleep(200 * time.Millisecond)

	// Verification should fail due to expired stamp
	err = signer.Verify(message, sig)
	require.Error(err)
	require.Equal(quantum.ErrQuantumStampExpired, err)
}
