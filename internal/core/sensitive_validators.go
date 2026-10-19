package core

import (
	"strings"
	"time"
)

// ValidLuhn ports app/validators.py:luhn_ok, ISO/IEC 7812-1. It validates
// the checksum, not issuance or an account; the detector owns format/length.
func ValidLuhn(value string) bool {
	if value == "" {
		return false
	}
	sum := 0
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		n := int(value[i] - '0')
		if (len(value)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// ValidCNID ports BTPII app/validators.py:is_valid_cn_id: GB 11643-1999 §5,
// mod-11 check character plus a real YYYYMMDD date, not identity verification.
func ValidCNID(value string) bool {
	if len(value) != 18 {
		return false
	}
	weights := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i, w := range weights {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		sum += int(value[i]-'0') * w
	}
	if _, err := time.Parse("20060102", value[6:14]); err != nil || value[6:10] == "0000" {
		return false
	}
	return strings.ToUpper(value[17:]) == string("10X98765432"[sum%11])
}
