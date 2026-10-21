//go:build darwin

package discovery

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os/exec"
	"strings"
)

// Named local exception: dsclOutputBudgetBytes reuses ConfigParseBudgetBytes's
// 2 MiB resource ceiling (report.go), following DirectoryEntryBudget's fail-closed
// enumeration precedent. This bounds buffered XML, not account count or a macOS
// limit; larger inventories fail rather than produce a partial observation.
const dsclOutputBudgetBytes = ConfigParseBudgetBytes

var (
	errDsclOutputBudget = errors.New("discovery: local account output budget exceeded")
	errDsclPlist        = errors.New("discovery: malformed local account plist")
	runDscl             = executeDscl
)

func enumerateLocalAccounts(ctx context.Context) ([]AccountHome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// dscl(1), /usr/share/man/man1/dscl.1: -plist emits XML, '.' selects
	// the local domain, and -readall accepts selected attribute keys. No shell,
	// filesystem /Users scan, /Search, LDAP or network-node fallback is used.
	data, err := runDscl(ctx, "/usr/bin/dscl", "-plist", ".", "-readall", "/Users",
		"RecordName", "UniqueID", "NFSHomeDirectory", "UserShell")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if errors.Is(err, errDsclOutputBudget) || len(data) > dsclOutputBudgetBytes {
		return nil, errDsclOutputBudget
	}
	if err != nil {
		return nil, errors.New("discovery: local account command failed")
	}
	accounts, err := decodeDsclAccounts(ctx, data)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return accounts, err
}

func executeDscl(ctx context.Context, name string, args ...string) ([]byte, error) {
	var output dsclOutputBuffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &output
	// A nil Stderr goes to the null device; never capture or expose diagnostics
	// that could include local account values (pkg.go.dev/os/exec#Cmd).
	err := cmd.Run()
	if output.exceeded {
		return nil, errDsclOutputBudget
	}
	if err != nil {
		return nil, err
	}
	return output.data.Bytes(), nil
}

// Keep the buffer named, not embedded: promoting bytes.Buffer.ReadFrom would
// let io.Copy bypass Write's ceiling (pkg.go.dev/io#Copy).
type dsclOutputBuffer struct {
	data     bytes.Buffer
	exceeded bool
}

func (b *dsclOutputBuffer) Write(p []byte) (int, error) {
	if len(p) > dsclOutputBudgetBytes-b.data.Len() {
		b.exceeded = true
		return 0, errDsclOutputBudget
	}
	return b.data.Write(p)
}

// dscl's plist is an array of dictionaries whose attribute values are arrays
// of strings. Precedent: puppetlabs/puppet, lib/puppet/provider/user/
// directoryservice.rb, get_all_users and generate_attribute_hash:
// https://github.com/puppetlabs/puppet/blob/main/lib/puppet/provider/user/directoryservice.rb
// Retain the first (canonical) RecordName as Puppet does; subsequent names are aliases.
type dsclXMLValue struct {
	XMLName  xml.Name
	Text     string         `xml:",chardata"`
	Children []dsclXMLValue `xml:",any"`
}

func decodeDsclAccounts(ctx context.Context, data []byte) ([]AccountHome, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	token, err := dsclDocumentToken(decoder)
	start, ok := token.(xml.StartElement)
	if err != nil || !ok || start.Name != (xml.Name{Local: "plist"}) {
		return nil, errDsclPlist
	}
	var root dsclXMLValue
	if decoder.DecodeElement(&root, &start) != nil || !dsclContainer(root, "plist") || len(root.Children) != 1 {
		return nil, errDsclPlist
	}
	if _, err := dsclDocumentToken(decoder); err != io.EOF {
		return nil, errDsclPlist
	}
	array := root.Children[0]
	if !dsclContainer(array, "array") {
		return nil, errDsclPlist
	}
	var accounts []AccountHome
	for _, record := range array.Children {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		account, eligible, err := dsclAccount(record)
		if err != nil {
			return nil, err
		}
		if eligible {
			accounts = append(accounts, account)
		}
	}
	return accounts, nil
}

// Reject non-whitespace text before/after the document: xml.Decoder.Decode by
// itself accepts leading text and does not check trailing content.
func dsclDocumentToken(decoder *xml.Decoder) (xml.Token, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return nil, errDsclPlist
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			// encoding/xml does not resolve the plist's external DTD.
		default:
			return token, nil
		}
	}
}

func dsclContainer(value dsclXMLValue, name string) bool {
	return value.XMLName == (xml.Name{Local: name}) && strings.TrimSpace(value.Text) == ""
}

func dsclAccount(record dsclXMLValue) (AccountHome, bool, error) {
	attributes, err := dsclAttributes(record)
	if err != nil {
		return AccountHome{}, false, err
	}
	names := attributes["dsAttrTypeStandard:RecordName"]
	if len(names) == 0 || names[0] == "" {
		return AccountHome{}, false, errDsclPlist
	}
	name := names[0]
	if name == "root" || strings.HasPrefix(name, "_") || strings.HasSuffix(name, "$") {
		return AccountHome{}, false, nil
	}
	ids, homes, shells := attributes["dsAttrTypeStandard:UniqueID"], attributes["dsAttrTypeStandard:NFSHomeDirectory"], attributes["dsAttrTypeStandard:UserShell"]
	if len(ids) != 1 || len(homes) != 1 || len(shells) != 1 || shells[0] == "" {
		return AccountHome{}, false, errDsclPlist
	}
	if !dsclEligibleLogin(name, ids[0], homes[0], shells[0]) {
		return AccountHome{}, false, nil
	}
	// Shared normalizeAccounts alone owns ID/home validation and deduplication.
	return AccountHome{ObservedLocalAccount: name, AccountID: ids[0], HomePath: homes[0]}, true, nil
}

func dsclAttributes(record dsclXMLValue) (map[string][]string, error) {
	if !dsclContainer(record, "dict") || len(record.Children)%2 != 0 {
		return nil, errDsclPlist
	}
	attributes := make(map[string][]string)
	for i := 0; i < len(record.Children); i += 2 {
		key, array := record.Children[i], record.Children[i+1]
		if key.XMLName != (xml.Name{Local: "key"}) || len(key.Children) != 0 || !dsclContainer(array, "array") {
			return nil, errDsclPlist
		}
		if _, exists := attributes[key.Text]; exists {
			return nil, errDsclPlist
		}
		values := make([]string, 0, len(array.Children))
		for _, value := range array.Children {
			if value.XMLName != (xml.Name{Local: "string"}) || len(value.Children) != 0 {
				return nil, errDsclPlist
			}
			values = append(values, value.Text)
		}
		attributes[key.Text] = values
	}
	return attributes, nil
}

func dsclEligibleLogin(name, id, home, shell string) bool {
	// Fleet users inventory: https://fleetdm.com/vitals/users (Query).
	// These filters bound eligibility, not humanness; preserve its exact sync case.
	if id == "0" || (name == "sync" && shell == "/bin/sync" && home != "") {
		return false
	}
	for _, suffix := range []string{"/false", "/nologin", "/shutdown", "/halt"} {
		if strings.HasSuffix(shell, suffix) {
			return false
		}
	}
	// No UID floor: Kandji documents legitimate sub-500 hidden administrators
	// and homes in /private/var: https://support.kandji.io/kb/create-user-accounts.
	return true
}
