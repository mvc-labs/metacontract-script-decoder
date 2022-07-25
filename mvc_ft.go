package script

import (
	"bytes"
	"encoding/binary"
)

func decodeMvcFT(scriptLen int, pkScript []byte, txo *TxoData) bool {
	dataLen := 0
	protoVersionLen := 0
	genesisIdLen := 0
	sensibleIdLen := 0
	useTokenIdHash := false
	if pkScript[scriptLen-109-1-1-1] == OP_RETURN &&
		pkScript[scriptLen-109-1-1] == 0x4c &&
		pkScript[scriptLen-109-1] == 0x6d {
		// <address(20 bytes)> +
		//<token amount(8 bytes)> +
		//<genesisHash(20 bytes)> +
		//<sensibleID(36 bytes)> +
		//<proto_version(4 bytes)> +
		//<proto_type(4 bytes)> +
		//<'metacontract'(12 bytes)> +
		//<dataLen(4 bytes)> +
		//<flag(1 bytes)>
		protoVersionLen = 4
		genesisIdLen = 20
		sensibleIdLen = 36
		dataLen = 1 + 1 + 76 + genesisIdLen // 0x4c + pushdata + data + genesisId
		useTokenIdHash = true
	} else {
		// error ft
		return false
	}

	protoTypeOffset := scriptLen - 17 - 4
	sensibleOffset := protoTypeOffset - protoVersionLen - sensibleIdLen

	genesisOffset := protoTypeOffset - protoVersionLen - genesisIdLen
	amountOffset := genesisOffset - 8
	addressOffset := amountOffset - 20
	// todo
	decimalOffset := addressOffset - 1
	symbolOffset := decimalOffset - 1 - 10
	nameOffset := symbolOffset - 20

	txo.CodeType = CodeType_FT

	ft := &FTData{
		Decimal: uint8(pkScript[decimalOffset]),
		Symbol:  string(bytes.TrimRight(pkScript[symbolOffset:symbolOffset+10], "\x00")),
		Name:    string(bytes.TrimRight(pkScript[nameOffset:nameOffset+20], "\x00")),
		Amount:  binary.LittleEndian.Uint64(pkScript[amountOffset : amountOffset+8]),
	}
	txo.FT = ft

	txo.HasAddress = true
	copy(txo.AddressPkh[:], pkScript[addressOffset:addressOffset+20])

	copy(txo.CodeHash[:], GetHash160(pkScript[:scriptLen-dataLen]))
	if useTokenIdHash {
		ft.SensibleId = make([]byte, sensibleIdLen)
		copy(ft.SensibleId, pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])

		// GenesisId is tokenIdHash
		txo.GenesisIdLen = 20
		copy(txo.GenesisId[:], GetHash160(pkScript[genesisOffset:genesisOffset+genesisIdLen]))
	} else {
		ft.SensibleId = make([]byte, genesisIdLen)
		copy(ft.SensibleId, pkScript[genesisOffset:genesisOffset+genesisIdLen])

		txo.GenesisIdLen = uint8(genesisIdLen)
		copy(txo.GenesisId[:], ft.SensibleId)
	}
	return true
}
