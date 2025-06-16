package sidchecks

import (
	"FindOldSIDTraces/sidmap"
	"fmt"

	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// CheckNTSD analyzes a Windows NT Security Descriptor byte array and validates all SIDs against a provided SID map.
// It checks both the Discretionary Access Control List (DACL) and System Access Control List (SACL) entries.
//
// Parameters:
//   - ntsdBytes: Byte array containing the NT Security Descriptor data
//   - allSIDMap: Reference to a SID map containing all valid SIDs to check against
//
// Returns:
//   - []string: A slice of audit messages for any unknown SIDs found in the security descriptor
//   - error: An error if parsing the security descriptor fails
func CheckNTSD(ntsdBytes []byte, allSIDMap *sidmap.AllSIDMap) ([]string, error) {
	var auditMessages []string

	// Parse the security descriptor
	ntsd := securitydescriptor.NewSecurityDescriptor()
	_, err := ntsd.Unmarshal(ntsdBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse security descriptor: %v", err)
	}

	// Check DACL
	if ntsd.DACL != nil {
		for _, ace := range ntsd.DACL.Entries {
			sid := ace.Identity.SID.String()
			if !allSIDMap.SIDExists(sid) {
				auditMessages = append(auditMessages, fmt.Sprintf("Unknown SID %s in DACL entry #%d of the security descriptor", sid, ace.Index))
			}
		}
	}

	// Check SACL
	if ntsd.SACL != nil {
		for _, ace := range ntsd.SACL.Entries {
			sid := ace.Identity.SID.String()
			if !allSIDMap.SIDExists(sid) {
				auditMessages = append(auditMessages, fmt.Sprintf("Unknown SID %s in SACL entry #%d of the security descriptor", sid, ace.Index))
			}
		}
	}

	return auditMessages, nil
}
