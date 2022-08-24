package script

import (
	"encoding/binary"
)

// decodeMvcNFT
// <op_pushdata> + <type specific data> + <proto header> + <data_len(4 bytes)> + <version(1 bytes)>
// <proto header> = <proto_version(4 bytes)> + <proto_type(4 bytes)> + <'metacontract'(12 bytes)>
// <nft type specific data> = <meta_outpoint(36 bytes)> + <address(20 bytes)> + <totalSupply(8 bytes)> + <tokenIndex(8 bytes)> + <genesisHash(20 bytes)> + <GenesisTxid(36 bytes)>
func decodeMvcNFT(scriptLen int, pkScript []byte, txo *TxoData) bool {
	//<meta_outpoint(36 bytes)> +
	//<address(20 bytes)> +
	//<totalSupply(8 bytes)> +
	//<tokenIndex(8 bytes)> +
	//<genesisHash(20 bytes)> +
	//<GenesisTxid(36 bytes)> +
	//<proto_version(4 bytes)> +
	//<proto_type(4 bytes)> +
	//<'metacontract'(12 bytes)>+
	//<data_len(4 bytes)> +
	//<version(1 bytes)>
	protoVersionLen := 4
	protoTypeLen := 4
	genesisHashLen := 20
	addressLen := 20
	sensibleIdLen := 36
	totalSupplyLen := 8
	tokenIndexLen := 8
	metaOutpointLen := 36
	dataLen := metaOutpointLen + addressLen + totalSupplyLen + tokenIndexLen + genesisHashLen + sensibleIdLen + protoTypeLen + protoVersionLen + 12 + 4 + 1

	if !(pkScript[scriptLen-dataLen-1-1-1] == OP_RETURN &&
		pkScript[scriptLen-dataLen-1-1] == 0x4c &&
		pkScript[scriptLen-dataLen-1] == byte(dataLen)) {
		// error nft
		return false

	}
	protoTypeOffset := scriptLen - 17 - protoTypeLen
	sensibleOffset := protoTypeOffset - protoVersionLen - sensibleIdLen
	genesisOffset := sensibleOffset - genesisHashLen
	tokenIndexOffset := genesisOffset - tokenIndexLen
	totalSupplyOffset := tokenIndexOffset - totalSupplyLen
	addressOffset := totalSupplyOffset - addressLen
	metaOutpointOffset := addressOffset - metaOutpointLen

	txo.CodeType = CodeType_NFT

	nft := &NFTData{
		SensibleId:  make([]byte, sensibleIdLen),
		TokenSupply: binary.LittleEndian.Uint64(pkScript[totalSupplyOffset : totalSupplyOffset+8]),
		TokenIndex:  binary.LittleEndian.Uint64(pkScript[tokenIndexOffset : tokenIndexOffset+8]),
	}
	txo.NFT = nft
	// code 部分=总长-push数-op return操作符
	copy(txo.CodeHash[:], GetHash160(pkScript[:scriptLen-dataLen-1-1]))
	copy(nft.SensibleId, pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])

	txo.HasAddress = true
	copy(txo.AddressPkh[:], pkScript[addressOffset:addressOffset+20])

	// GenesisId: hash160(<genesisHash(20 bytes)> + <sensibleID(36 bytes)>)
	txo.GenesisIdLen = 20
	genesisPreHash := make([]byte, sensibleIdLen+genesisHashLen)
	copy(genesisPreHash[:genesisHashLen], pkScript[genesisOffset:genesisOffset+genesisHashLen])
	copy(genesisPreHash[genesisHashLen:], pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])
	copy(txo.GenesisId[:], GetHash160(genesisPreHash))

	nft.MetaOutputIndex = binary.LittleEndian.Uint32(pkScript[metaOutpointOffset+32 : metaOutpointOffset+metaOutpointLen])
	copy(nft.MetaTxId[:], pkScript[metaOutpointOffset:metaOutpointOffset+32])
	ReverseBytesInPlace(nft.MetaTxId[:])

	return true
}
