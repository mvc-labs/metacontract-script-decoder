package script

import (
	"encoding/binary"
)

// decodeMvcUnique
// <op_pushdata> + <type specific data> + <proto header> + <data_len(4 bytes)> + <version(1 bytes)>
// <proto header> = <proto_version(4 bytes)> + <proto_type(4 bytes)> + <'metacontract'(12 bytes)>
// <unique type specific data> = <unique custom data> + <custom data length(4 bytes)> + <genesisTxid(36 bytes)>
func decodeMvcUnique(scriptLen int, pkScript []byte, txo *TxoData) bool {
	//<unique custom data> +
	//<custom data length(4 bytes)> +
	//<genesisTxid(36 bytes)> +
	//<proto_version(4 bytes)> +
	//<proto_type(4 bytes)> +
	//<'metacontract'(12 bytes)>+
	//<data_len(4 bytes)> +
	//<version(1 bytes)>
	lengthAfterCustomData := 1 + 4 + 12 + 4 + 4 + 36 + 4
	customDataSize := int(binary.LittleEndian.Uint32(pkScript[scriptLen-lengthAfterCustomData : scriptLen-lengthAfterCustomData+4]))
	totalDataLen := lengthAfterCustomData + customDataSize

	protoVersionLen := 4
	protoTypeLen := 4
	sensibleIdLen := 36

	// check data length and op_return code
	// decide push data length
	pushType := GetOpPushTypeByDataSize(totalDataLen)
	opPushByteLen := GetOpPushByteLength(pushType)
	if !checkOpReturnPositionAndDataLength(scriptLen, pkScript, totalDataLen, pushType, opPushByteLen) {
		return false
	}
	protoTypeOffset := scriptLen - 17 - protoTypeLen
	sensibleOffset := protoTypeOffset - protoVersionLen - sensibleIdLen
	customDataOffset := sensibleOffset - 4 - customDataSize
	txo.CodeType = CodeType_UNIQUE
	txo.HasAddress = false

	unique := &UniqueData{}
	txo.Uniq = unique

	// 复制sensibleId
	unique.SensibleId = make([]byte, sensibleIdLen)
	copy(unique.SensibleId, pkScript[sensibleOffset:sensibleOffset+sensibleIdLen])
	// 复制customData
	unique.CustomData = make([]byte, customDataSize)
	copy(unique.CustomData, pkScript[customDataOffset:customDataOffset+customDataSize])

	// code 部分=总长-totalDataLen-pushCode-pushSizeBytes-opReturn
	copy(txo.CodeHash[:], GetHash160(pkScript[:scriptLen-totalDataLen-1-opPushByteLen]))

	// GenesisId: hash160(<genesisHash(20 bytes)> + <sensibleID(36 bytes)>)
	txo.GenesisIdLen = 20
	copy(txo.GenesisId[:], GetHash160(unique.SensibleId))
	return true
}

// checkOpReturnPositionAndDataLength check op_return position and data length, true if ok
func checkOpReturnPositionAndDataLength(scriptLen int, pkScript []byte, totalDataLen, pushType, opPushByteLen int) bool {
	// op_return op_pushdata_op data_len_byte data
	if !(pkScript[scriptLen-totalDataLen-1-opPushByteLen-1] == OP_RETURN) {
		return false
	}
	lengthBytes := pkScript[scriptLen-totalDataLen-opPushByteLen : scriptLen-totalDataLen]
	switch opPushByteLen {
	case 0:
		if pushType != totalDataLen {
			return false
		}
		break
	case 1:
		if int(lengthBytes[0]) != totalDataLen {
			return false
		}
		break
	case 2:
		if int(binary.LittleEndian.Uint16(lengthBytes)) != totalDataLen {
			return false
		}
		break
	case 4:
		if int(binary.LittleEndian.Uint32(lengthBytes)) != totalDataLen {
			return false
		}
		break
	}
	return true
}
