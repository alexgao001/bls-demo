package main

import (
	"github.com/prysmaticlabs/prysm/crypto/bls/blst"
	blscmn "github.com/prysmaticlabs/prysm/crypto/bls/common"
)

type VoteSignerV2 struct {
	privkey blscmn.SecretKey
	pubKey  blscmn.PublicKey
}

func NewVoteSignerV2(privkey []byte) (*VoteSignerV2, error) {
	privKey, err := blst.SecretKeyFromBytes(privkey)
	if err != nil {
		return nil, err
	}
	pubKey := privKey.PublicKey()
	return &VoteSignerV2{
		privkey: privKey,
		pubKey:  pubKey,
	}, nil
}

// SignVote sign a vote, data is used to signed to generate the signature
func (signer *VoteSignerV2) SignVote(vote *Vote, data []byte) error {
	signature := signer.privkey.Sign(data[:])
	vote.EventHash = append(vote.EventHash, data[:]...)
	copy(vote.PubKey[:], signer.pubKey.Marshal()[:])
	copy(vote.Signature[:], signature.Marshal()[:])
	return nil
}
