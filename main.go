package main

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type Packages []Package

type Package struct {
	ChannelId uint8
	Sequence  uint64
	Payload   []byte
}

func main() {

	// Mimic there are validators
	privateKey1 := "0cb5c2dd492758b1494919c7376d2cedaa41f923d431e4dcae8b66a388ba9d30"
	privateKey2 := "0857c876d59763458f085d08689752acb8c1e510c35ec92999489e76e9a1f98e"

	validatorSigner1, _ := NewVoteSignerV2(common.Hex2Bytes(privateKey1))
	validatorSigner2, _ := NewVoteSignerV2(common.Hex2Bytes(privateKey2))

	// packages，will be sign individually by validator 1 and 2
	payload, _ := hex.DecodeString("746573745061796c6f6164") // "testPayload"
	aggPkgs := make(Packages, 0)
	pkg1 := Package{
		ChannelId: 1,
		Sequence:  1,
		Payload:   payload,
	}
	aggPkgs = append(aggPkgs, pkg1)
	pkg2 := Package{
		ChannelId: 2,
		Sequence:  1,
		Payload:   payload,
	}
	aggPkgs = append(aggPkgs, pkg2)
	pkg3 := Package{
		ChannelId: 3,
		Sequence:  1,
		Payload:   payload,
	}
	aggPkgs = append(aggPkgs, pkg3)

	// RLP encode packages to bytes
	encBts, _ := rlp.EncodeToBytes(aggPkgs)
	// Hash the rlp-encoded bytes, can eventHash
	eventHash := crypto.Keccak256Hash(encBts).Bytes()

	var vote1 Vote
	validatorSigner1.SignVote(&vote1, eventHash)
	println("validator 1 signature: " + hex.EncodeToString(vote1.Signature[:])) // validator 1 signature: b12226b5f629a49b39ae342e4eb1a35cd7f3d9dd7dec1d4cb0e40b74ff3cf3c2053b921e896680215c3cf157af3a8d7a0dc2e9e9a3d88584bac3001fd2bfb520941d4e7cda845fcabdab06d62875a8fdf0cec4f5a256ec81e9f99e93ba0f7a8c
	vote1.Verify(eventHash)

	var vote2 Vote
	validatorSigner2.SignVote(&vote2, eventHash)
	println("validator 2 signature: " + hex.EncodeToString(vote2.Signature[:])) // validator 2 signature: 8e91040ae7849a1a0eacf5a8714789b07e1946dd46361550288299937f8be6cbc371fd90805b058494593304adaa7af711b0043550081430a854ce82391a33a84e93c3a5a38d003aeccca4018a911b7feede153f7f5b943c74ff012b7acfc77e
	vote2.Verify(eventHash)

	var votes []*Vote
	votes = append(votes, &vote1)
	votes = append(votes, &vote2)
	aggreatedSigature, _ := AggregatedSignature(votes)
	println("aggregated sig is: " + hex.EncodeToString(aggreatedSigature)) //aggregated sig is: acbd766fb53299f21bee629ffbde5eb6231588e96362d1910b1788a570b9ca01fa9e4241876cf831ebbfd904604382a90e699a9f8fd997dce944cc009e969c5ef1343424210a050c30765e25fcba9a9050c682e47dc508582e60c5c30a691109

}
