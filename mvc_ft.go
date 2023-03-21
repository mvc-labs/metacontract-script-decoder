package script

import (
	"bytes"
	"encoding/binary"
)

// decodeMvcFT
// <op_pushdata> + <type specific data> + <proto header> + <data_len(4 bytes)> + <version(1 bytes)>
// <proto header> = <proto_version(4 bytes)> + <proto_type(4 bytes)> + <'metacontract'(12 bytes)>
// <token type specific data> = <name(40 bytes)> + <symbol(20 bytes)> + <decimal(1 bytes)> + <address(20 bytes)> + <token amount(8 bytes)> + <genesisHash(20 bytes)> + <sensibleID(36 bytes)>
func decodeMvcFT(scriptLen int, pkScript []byte, txo *TxoData) bool {
	//<name(40 bytes)> +
	//<symbol(20 bytes)> +
	//<decimal(1 bytes)> +
	//<address(20 bytes)> +
	//<token amount(8 bytes)> +
	//<genesisHash(20 bytes)> +
	//<sensibleID(36 bytes)> +
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
	decimalLen := 1
	symbolLen := 20
	nameLen := 40
	amountLen := 8
	dataLen := nameLen + symbolLen + decimalLen + addressLen + amountLen + genesisHashLen + sensibleIdLen + protoTypeLen + protoVersionLen + 12 + 4 + 1

	if !(pkScript[scriptLen-dataLen-1-1-1] == OP_RETURN &&
		pkScript[scriptLen-dataLen-1-1] == 0x4c &&
		pkScript[scriptLen-dataLen-1] == byte(dataLen)) {
		// error ft
		return false

	}
	protoTypeOffset := scriptLen - 17 - protoTypeLen
	sensibleOffset := protoTypeOffset - protoVersionLen - sensibleIdLen
	genesisOffset := sensibleOffset - genesisHashLen
	amountOffset := genesisOffset - amountLen
	addressOffset := amountOffset - addressLen
	decimalOffset := addressOffset - decimalLen
	symbolOffset := decimalOffset - symbolLen
	nameOffset := symbolOffset - nameLen

	txo.CodeType = CodeType_FT

	ft := &FTData{
		Decimal: pkScript[decimalOffset],
		Symbol:  string(bytes.TrimRight(pkScript[symbolOffset:symbolOffset+symbolLen], "\x00")),
		Name:    string(bytes.TrimRight(pkScript[nameOffset:nameOffset+nameLen], "\x00")),
		Amount:  binary.LittleEndian.Uint64(pkScript[amountOffset : amountOffset+amountLen]),
	}
	txo.FT = ft

	txo.HasAddress = true
	copy(txo.AddressPkh[:], pkScript[addressOffset:addressOffset+addressLen])

	// code 部分=总长-push数
	copy(txo.CodeHash[:], GetHash160(pkScript[:scriptLen-dataLen-1-1]))
	ft.SensibleId = make([]byte, sensibleIdLen)
	copy(ft.SensibleId, pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])

	// GenesisId: hash160(<genesisHash(20 bytes)> + <sensibleID(36 bytes)>)
	txo.GenesisIdLen = 20
	genesisPreHash := make([]byte, sensibleIdLen+genesisHashLen)
	copy(genesisPreHash[:genesisHashLen], pkScript[genesisOffset:genesisOffset+genesisHashLen])
	copy(genesisPreHash[genesisHashLen:], pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])
	copy(txo.GenesisId[:], GetHash160(genesisPreHash))
	return true
}
