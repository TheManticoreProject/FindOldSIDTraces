package sidmap

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/winacl/sid"
)

// AllSIDMap is a map of all known SIDs and their corresponding distinguished names.
// It is used to validate SIDs in security descriptors and other Windows security-related data.
type AllSIDMap struct {
	AllSIDMap map[string]string
}

// PopulateSIDMap populates the AllSIDMap with all known SIDs and their corresponding distinguished names.
// It uses LDAP to query the domain controller for all SIDs in the domain.
//
// Parameters:
//   - domainController: The domain controller to query for SIDs
//   - ldapPort: The port to use for LDAP queries
//   - creds: The credentials to use for LDAP queries
//   - useLdaps: Whether to use LDAP over TLS
//
// Returns:
//   - error: An error if the LDAP query fails
func (a *AllSIDMap) PopulateSIDMap(domainController string, ldapPort int, creds *credentials.Credentials, useLdaps bool) {
	logger.Info(fmt.Sprintf("Populating known SIDs map for %s", creds.Domain))

	a.AllSIDMap = make(map[string]string)

	for wellKnownSID, sidName := range sid.WellKnownSIDs {
		a.AllSIDMap[wellKnownSID] = sidName
	}

	ldapSession := ldap.Session{}
	ldapSession.InitSession(domainController, ldapPort, creds, useLdaps, false)
	success, err := ldapSession.Connect()
	if !success {
		logger.Warn(fmt.Sprintf("Error connecting to LDAP: %s", err))
		return
	}

	searchResults, err := ldapSession.QueryAllNamingContexts(
		"(&(objectClass=*)(objectSid=*))",
		[]string{"distinguishedName", "objectSid"},
		ldap.ScopeWholeSubtree,
	)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error performing LDAP search: %s", err))
		return
	}

	for _, entry := range searchResults {
		distinguishedName := entry.GetAttributeValue("distinguishedName")

		sidValue := entry.GetEqualFoldAttributeValues("objectSid")

		if len(sidValue) == 0 {
			continue
		}

		s := sid.SID{}
		_, err = s.Unmarshal([]byte(sidValue[0]))
		if err != nil {
			logger.Warn(fmt.Sprintf("Error parsing SID: %s", err))
			continue
		}
		a.AllSIDMap[s.String()] = distinguishedName
	}

	logger.Info(fmt.Sprintf("Found %d known SIDs", len(a.AllSIDMap)))
}

// SIDExists checks if a given SID exists in the AllSIDMap.
//
// Parameters:
//   - sid: The SID to check
//
// Returns:
//   - bool: True if the SID exists in the AllSIDMap, false otherwise
func (a *AllSIDMap) SIDExists(sid string) bool {
	_, exists := a.AllSIDMap[sid]
	return exists
}

// GetDistinguishedNameOfSID returns the distinguished name of a given SID.
//
// Parameters:
//   - sid: The SID to get the distinguished name of
//
// Returns:
//   - string: The distinguished name of the SID
func (a *AllSIDMap) GetDistinguishedNameOfSID(sid string) string {
	return a.AllSIDMap[sid]
}
