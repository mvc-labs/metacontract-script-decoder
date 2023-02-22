package script

import (
	"encoding/binary"
)

// nft sell
func decodeMvcNFTSell(scriptLen int, pkScript []byte, txo *TxoData) bool {
	//<codehash(20 bytes)> +
	//<genesis(20 bytes)>
	//<tokenIndex(8 bytes)>
	//<sellerAddress(20 bytes)>
	//<satoshisPrice(8 bytes)> +
	//<nftID(20 bytes)> +
	//<proto_version(4 bytes)> +
	//<proto_type(4 bytes)> +
	//<'metacontract'(12 bytes)>+
	//<data_len(4 bytes)> +
	//<version(1 bytes)>
	nftIdLen := 20
	satoshiPriceLen := 8
	sellerAddressLen := 20
	tokenIndexLen := 8
	genesisHashLen := 20
	codeHashLen := 20
	protoVersionLen := 4
	protoTypeLen := 4
	dataLen := codeHashLen + genesisHashLen + tokenIndexLen + sellerAddressLen + satoshiPriceLen + nftIdLen + protoTypeLen + protoVersionLen + 12 + 4 + 1
	// check size
	if !(pkScript[scriptLen-dataLen-1-1-1] == OP_RETURN &&
		pkScript[scriptLen-dataLen-1-1] == 0x4c &&
		pkScript[scriptLen-dataLen-1] == byte(dataLen)) {
		// error nft
		return false
	}

	protoVersionOffset := scriptLen - 17 - protoTypeLen
	nftIdOffset := protoVersionOffset - nftIdLen
	priceOffset := nftIdOffset - satoshiPriceLen
	addressOffset := priceOffset - sellerAddressLen
	tokenIndexOffset := addressOffset - tokenIndexLen
	genesisOffset := tokenIndexOffset - genesisHashLen
	codeHashOffset := genesisOffset - codeHashLen

	txo.CodeType = CodeType_NFT_SELL

	nft := &NFTSellData{
		TokenIndex: binary.LittleEndian.Uint64(pkScript[tokenIndexOffset : tokenIndexOffset+tokenIndexLen]),
		Price:      binary.LittleEndian.Uint64(pkScript[priceOffset : priceOffset+satoshiPriceLen]),
	}
	txo.NFTSell = nft
	// txo.CodeHash = GetHash160(pkScript[:scriptLen-dataLen])

	txo.GenesisIdLen = uint8(genesisHashLen)
	copy(txo.CodeHash[:], pkScript[codeHashOffset:codeHashOffset+codeHashLen])
	copy(txo.GenesisId[:], pkScript[genesisOffset:genesisOffset+genesisHashLen])
	txo.HasAddress = true
	// seller
	copy(txo.AddressPkh[:], pkScript[addressOffset:addressOffset+sellerAddressLen])
	return true
}
