package eval

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Values/lengths: ISO/IEC 7812 Luhn; GB 11643-1999 §5 checksum weights;
// RFC 5322 §3.4.1 via net/mail. Phone pattern is ported from
// libphonenumber v9.0.17 PhoneNumberMetadata.xml, CN/mobile (Apache-2.0),
// adapting decimal-digit notation for Go regexp:
// https://github.com/google/libphonenumber/blob/v9.0.17/resources/PhoneNumberMetadata.xml
var cnMobile = regexp.MustCompile(`^(?:1740[0-5][0-9]{6}|1(?:[38][0-9]|4[57]|[59][0-35-9]|6[25-7]|7[0-35-8])[0-9]{8})$`)
var digitsOnly = regexp.MustCompile(`^[0-9]+$`)
var idWeights = []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

const idChecks = "10X98765432"

func luhn(s string) bool {
	if !digitsOnly.MatchString(s) {
		return false
	}
	total := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
		double = !double
	}
	return total%10 == 0
}
func idChecksum(s string) byte {
	sum := 0
	for i, w := range idWeights {
		sum += int(s[i]-'0') * w
	}
	return idChecks[sum%11]
}
func ValidatePII(kind, value string) bool {
	switch kind {
	case "Card":
		return len(value) > 1 && luhn(value)
	case "ID":
		if len(value) != 18 || !digitsOnly.MatchString(value[:17]) || idChecksum(value[:17]) != value[17] {
			return false
		}
		date, e := time.Parse("20060102", value[6:14])
		return e == nil && date.Format("20060102") == value[6:14] && value[14:17] != "000"
	case "Email":
		a, e := mail.ParseAddress(value)
		return e == nil && a.Name == "" && a.Address == value && strings.Contains(value, "@")
	case "Phone":
		return cnMobile.MatchString(value)
	default:
		return false
	}
}
func UTF16Slice(text string, span Span) string {
	u := utf16.Encode([]rune(text))
	if span.StartUTF16 < 0 || span.EndUTF16 > len(u) || span.StartUTF16 > span.EndUTF16 {
		return ""
	}
	return string(utf16.Decode(u[span.StartUTF16:span.EndUTF16]))
}
func GenerateDev() []PIIRecord { rows, _ := GeneratePII("dev"); return rows }

// GeneratePII requires an explicit seed: workers call only GenerateDev; the
// sealed acceptance seed is lead-supplied after freeze, never selected here.
// 20 records = WARMUP-20 (plan named local exception), not a statistical sample:
// 2 languages × 2 surfaces × (4 documented entity types + benign control).
// Presidio synthetic-template precedent: github.com/microsoft/presidio-research.
func GeneratePII(seed string) ([]PIIRecord, error) {
	if seed == "" {
		return nil, errors.New("explicit synthetic seed required")
	}
	rows := []PIIRecord{}
	for _, lang := range []string{"EN", "ZH"} {
		for _, surface := range []string{"prompt", "tool_result"} {
			for _, kind := range []string{"Email", "Phone", "Card", "ID", "benign"} {
				sum := sha256.Sum256([]byte(seed + "/" + lang + "/" + surface + "/" + kind))
				var value string
				switch kind {
				case "Email":
					value = fmt.Sprintf("synthetic-%x@example.invalid", sum[:4]) // RFC 2606 reserved .invalid.
				case "Phone":
					value = "138"
					for _, v := range sum[:8] {
						value += strconv.Itoa(int(v % 10))
					}
				case "Card":
					value = "000000"
					for _, v := range sum[:9] {
						value += strconv.Itoa(int(v % 10))
					}
					for d := 0; d < 10; d++ {
						if luhn(value + strconv.Itoa(d)) {
							value += strconv.Itoa(d)
							break
						}
					}
				case "ID":
					value = fmt.Sprintf("11010519900102%03d", int(sum[0])+1)
					value += string(idChecksum(value))
				}
				prefix := "SYNTHETIC FIXTURE (not a real identity): "
				// Authored synthetic context, not benchmark-derived text.
				if lang == "ZH" {
					prefix = "合成测试记录（非真实身份）："
				}
				row := PIIRecord{ID: Digest([]string{seed, lang, surface, kind}), Text: prefix + value, Language: lang, Surface: surface, Seed: seed, Entities: []Entity{}}
				if kind != "benign" {
					start := len(utf16.Encode([]rune(prefix)))
					row.Entities = []Entity{{Type: kind, Span: Span{start, start + len(utf16.Encode([]rune(value)))}}}
				}
				rows = append(rows, row)
			}
		}
	}
	return rows, nil
}
