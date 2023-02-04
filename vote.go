package main

import (
	"encoding/hex"

	"github.com/prysmaticlabs/prysm/crypto/bls"
	"github.com/prysmaticlabs/prysm/crypto/bls/common"
)

type Vote struct {
	PubKey    [48]byte
	Signature [96]byte
	EvenType  int
	EventHash []byte
}

func (vote *Vote) Verify(eventHash []byte) {
	blsPubKey, err := bls.PublicKeyFromBytes(vote.PubKey[:])

	if err != nil {
		return
	}
	sig, err := bls.SignatureFromBytes(vote.Signature[:])

	if err != nil {
		return
	}
	if !sig.Verify(blsPubKey, eventHash[:]) {
		return
	}
	println("successfully verified")
}

func AggregatedSignatureV1(votes []*Vote) (common.Signature, error) {
	// Prepare aggregated vote signature
	voteAddrSet := make(map[string]struct{}, len(votes))
	signatures := make([][]byte, 0, len(votes))
	for _, v := range votes {
		voteAddrSet[hex.EncodeToString(v.PubKey[:])] = struct{}{}
		signatures = append(signatures, v.Signature[:])
	}
	sigs, err := bls.MultipleSignaturesFromBytes(signatures)
	if err != nil {
		return nil, err
	}
	return bls.AggregateSignatures(sigs), nil
}

func AggregatedSignature(votes []*Vote) ([]byte, error) {
	// Prepare aggregated vote signature
	voteAddrSet := make(map[string]struct{}, len(votes))
	signatures := make([][]byte, 0, len(votes))
	for _, v := range votes {
		voteAddrSet[hex.EncodeToString(v.PubKey[:])] = struct{}{}
		signatures = append(signatures, v.Signature[:])
	}
	sigs, err := bls.MultipleSignaturesFromBytes(signatures)
	if err != nil {
		return nil, err
	}
	return bls.AggregateSignatures(sigs).Marshal(), nil
}
