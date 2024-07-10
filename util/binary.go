package util

import (
	"fmt"
	"strconv"
)

func DecodeBinaryStringToBytes(data string) []byte {
	var result []byte
	i := 0
	for i < len(data) {
		if data[i] == '\\' {
			i++
			switch data[i] {
			case '0':
				result = append(result, 0)
			case 'a':
				result = append(result, '\a')
			case 'b':
				result = append(result, '\b')
			case 'f':
				result = append(result, '\f')
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case 'v':
				result = append(result, '\v')
			case 'x':
				if i+2 >= len(data) {
					panic("Invalid hex - " + data)
				} else {
					hex, err := strconv.ParseInt(data[i+1:i+3], 16, 16)
					if err != nil {
						panic("Invalid hex - " + err.Error())
					}
					result = append(result, byte(hex))
					i += 2
				}
			default:
				result = append(result, '\\', data[i])
			}
		} else {
			result = append(result, data[i])
		}
		i++

	}
	return result
}

func EncodeBannerString(data []byte) string {
	var result string
	for _, b := range data {
		if b == '\\' {
			result += "\\\\"
		} else if b == '\a' {
			result += "\\a"
		} else if b == '\b' {
			result += "\\b"
		} else if b == '\f' {
			result += "\\f"
		} else if b == '\n' {
			result += "\n"
		} else if b == '\r' {
			result += "\r"
		} else if b == '\t' {
			result += "\t"
		} else if b == '\v' {
			result += "\\v"
		} else if b < 32 || b > 126 {
			result += fmt.Sprintf("\\x%02x", b)
		} else {
			result += string(b)
		}
	}
	return result
}

func EncodeBinaryString(data []byte) string {
	var result string
	for _, b := range data {
		if b == 0 {
			result += "\\0"
		} else if b == '\a' {
			result += "\\a"
		} else if b == '\b' {
			result += "\\b"
		} else if b == '\f' {
			result += "\\f"
		} else if b == '\n' {
			result += "\\n"
		} else if b == '\r' {
			result += "\\r"
		} else if b == '\t' {
			result += "\\t"
		} else if b == '\v' {
			result += "\\v"
		} else if b < 32 || b > 126 {
			result += fmt.Sprintf("\\x%02x", b)
		} else {
			result += string(b)
		}
	}
	return result
}
