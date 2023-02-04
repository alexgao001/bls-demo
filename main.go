package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/prysmaticlabs/prysm/crypto/bls/blst"
	blscmn "github.com/prysmaticlabs/prysm/crypto/bls/common"
)

func main() {
	// Mimic there are validators
	privateKey1 := "098318f0e07a319cfa1efcaef5b963f94d59b5a69718fce6251a28b0846868bd"
	privateKey2 := "414e8bf69a9ca2fd3d5257fed0dd7a422f1743565e6080cc324815a6e929c770"
	privateKey3 := "39fcb770cc295d78cf77a1b14f9ab8016b2ef73e1650baf90c95a9f644fbdb6b"

	validatorSigner1, _ := NewVoteSignerV2(common.Hex2Bytes(privateKey1))
	validatorSigner2, _ := NewVoteSignerV2(common.Hex2Bytes(privateKey2))
	validatorSigner3, _ := NewVoteSignerV2(common.Hex2Bytes(privateKey3))

	var pubKeys []blscmn.PublicKey
	prK1, _ := blst.SecretKeyFromBytes(common.Hex2Bytes(privateKey1))
	publicKey1 := prK1.PublicKey()
	pubKeys = append(pubKeys, publicKey1)
	prK2, _ := blst.SecretKeyFromBytes(common.Hex2Bytes(privateKey2))
	publicKey2 := prK2.PublicKey()
	pubKeys = append(pubKeys, publicKey2)
	prK3, _ := blst.SecretKeyFromBytes(common.Hex2Bytes(privateKey3))
	publicKey3 := prK3.PublicKey()
	pubKeys = append(pubKeys, publicKey3)

	// cross-cahin tx from gnfd
	tx := GreenfieldRelayTransaction{
		SrcChainId:    1,
		DestChainId:   2,
		ChannelId:     1,
		Sequence:      3,
		PackageType:   0,
		TxTime:        1675490707,
		PayLoad:       "eb7b9476d244ce05c3de4bbc6fdd7f56379b145709ade9941ac642f1329404e04850e1dee5e0abe903e62211",
		RelayerFee:    "1",
		AckRelayerFee: "0",
	}

	paylaod, _ := AggregatePayloadForTx(&tx)
	eventHash := crypto.Keccak256Hash(paylaod).Bytes()

	var vote1 Vote
	validatorSigner1.SignVote(&vote1, eventHash[:])
	println("relayer 1 signature: " + hex.EncodeToString(vote1.Signature[:])) // relayer 1 signature: 8816650dc36341c02e941b5cdbd7c16b512378f6eccbcd4480fa095164a42fd73a412529d8f312749d7892c97a920626189f3c0e36b479fb228be9c081c4137a089f5672abb7303eac1ee1eebe951758bd4b2f97bcef95207ecf77f29eb351d8
	vote1.Verify(eventHash[:])

	var vote2 Vote
	validatorSigner2.SignVote(&vote2, eventHash[:])
	println("relayer 2 signature: " + hex.EncodeToString(vote2.Signature[:])) // relayer 2 signature: a4136d4fe5d483f4176be4d982b0303c8f367b42bc14927fee14476397619e94657e0bc2a2b6cae7cd1c091a0b00080412e1c36ca6f81cc8014dd592fe975f336dd6c281b8a1f97d6eb60a2c0e227ccfb72ddb766357a7d7d4511f10bfffd944
	vote2.Verify(eventHash[:])

	var vote3 Vote
	validatorSigner3.SignVote(&vote3, eventHash[:])
	println("relayer 3 signature: " + hex.EncodeToString(vote3.Signature[:])) // relayer 3 signature: 830b8e892ee83c5cfbcec0b4e943c70e83a5ad9c6bfd9c7eecf262e29971c79b56b612842140ff397ae4166768e623960f79619b834cd4d24746c73c1cc0656836ec3b9fc2652fc0df017d9c83b3024f632e99e8223362ce082ec5ff4974f79e
	vote3.Verify(eventHash[:])

	var votes []*Vote
	votes = append(votes, &vote1)
	votes = append(votes, &vote2)
	votes = append(votes, &vote3)
	aggreatedSigature, _ := AggregatedSignatureV1(votes)

	println("aggregated sig is: " + hex.EncodeToString(aggreatedSigature.Marshal())) //aggregated sig is: b352e9b52ae49bc6ffaf7e975dd7d924ece56b709c88869e22bc832852bf7e033a420f6ca73b74403c46df9f601e323b194602e2ac1fa293f3badf3a306451afa4d071314b73428e99a4da5e444147fe001cb7c7b3d3603a521cbf340e6b1128

}

type GreenfieldRelayTransaction struct {
	Id            int64
	SrcChainId    uint32
	DestChainId   uint32
	ChannelId     uint8
	Sequence      uint64
	PackageType   uint32
	Height        uint64
	PayLoad       string
	RelayerFee    string
	AckRelayerFee string
	TxTime        int64
}

func AggregatePayloadForTx(tx *GreenfieldRelayTransaction) ([]byte, error) {
	var aggregatedPayload []byte

	aggregatedPayload = append(aggregatedPayload, Uint16ToBytes(uint16(tx.SrcChainId))...)
	aggregatedPayload = append(aggregatedPayload, Uint16ToBytes(uint16(tx.DestChainId))...)
	aggregatedPayload = append(aggregatedPayload, tx.ChannelId)
	aggregatedPayload = append(aggregatedPayload, Uint64ToBytes(tx.Sequence)...)
	aggregatedPayload = append(aggregatedPayload, uint8(tx.PackageType))
	aggregatedPayload = append(aggregatedPayload, Uint64ToBytes(uint64(tx.TxTime))...)

	// relayerfee big.Int
	relayerFeeBts, err := txFeeToBytes(tx.RelayerFee)
	if err != nil {
		return nil, err
	}
	aggregatedPayload = append(aggregatedPayload, relayerFeeBts...)

	if tx.PackageType == uint32(sdk.SynCrossChainPackageType) {
		ackRelayerFeeBts, err := txFeeToBytes(tx.AckRelayerFee)
		if err != nil {
			return nil, err
		}
		aggregatedPayload = append(aggregatedPayload, ackRelayerFeeBts...)
	}
	aggregatedPayload = append(aggregatedPayload, common.Hex2Bytes(tx.PayLoad)...)
	return aggregatedPayload, nil
}

func txFeeToBytes(txFee string) ([]byte, error) {
	fee, ok := new(big.Int).SetString(txFee, 10)
	if !ok {
		return nil, errors.New("failed to convert tx fee")
	}
	feeBytes := make([]byte, 32)
	fee.FillBytes(feeBytes)
	return feeBytes, nil
}

func Uint16ToBytes(num uint16) []byte {
	bt := make([]byte, 2)
	binary.BigEndian.PutUint16(bt, num)
	return bt
}

func Uint64ToBytes(num uint64) []byte {
	bt := make([]byte, 8)
	binary.BigEndian.PutUint64(bt, num)
	return bt
}
