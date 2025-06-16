package search

import (
	"FindOldSIDTraces/sidchecks"
	"FindOldSIDTraces/sidmap"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// OldSIDTrace is a struct that contains the results of the search for old SID traces.
type OldSIDTrace struct {
	// This is a map of SID to a list of distinguished names to a list of messages
	// describing the old SID traces found on that object.
	Results map[string][]string
}

// SearchOldSIDTraces searches for traces of old SIDs in the Active Directory environment.
// It takes an AllSIDMap containing known SIDs, domain controller information, and credentials
// as input. The function performs an LDAP search across all naming contexts to find objects
// with security descriptors (nTSecurityDescriptor) and RBCD settings (msDS-AllowedToActOnBehalfOfOtherIdentity).
// For each object found, it checks both the security descriptor and RBCD settings for any SIDs
// that are not present in the provided AllSIDMap. Results are stored in the OldSIDTrace struct's
// Results map, where each key is a SID and the value is a list of messages describing where
// that SID was found.
//
// Parameters:
//   - allSIDMap: Reference to a SID map containing all valid SIDs to check against
//   - domainController: The domain controller to query for SIDs
//   - ldapPort: The port to use for LDAP queries
//   - creds: The credentials to use for LDAP queries
//   - useLdaps: Whether to use LDAP over TLS
//
// Returns:
//   - error: An error if the LDAP search fails
func (o *OldSIDTrace) SearchOldSIDTraces(allSIDMap *sidmap.AllSIDMap, domainController string, ldapPort int, creds *credentials.Credentials, useLdaps bool) {
	logger.Info(fmt.Sprintf("Searching for old SID traces on %s", creds.Domain))

	if o.Results == nil {
		o.Results = make(map[string][]string)
	}

	ldapSession := ldap.Session{}
	ldapSession.InitSession(domainController, ldapPort, creds, useLdaps, false)
	success, err := ldapSession.Connect()
	if !success {
		logger.Warn(fmt.Sprintf("Error connecting to LDAP: %s", err))
		return
	}

	searchResults, err := ldapSession.QueryAllNamingContexts(
		"(objectClass=*)",
		[]string{"distinguishedName", "nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity"},
		ldap.ScopeWholeSubtree,
	)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error performing LDAP search: %s", err))
		return
	}

	for _, entry := range searchResults {
		auditMessages := []string{}

		// Check ntsd
		nstdMessages := []string{}
		ntsdValues := entry.GetEqualFoldRawAttributeValues("nTSecurityDescriptor")
		if len(ntsdValues) != 0 {
			results, err := sidchecks.CheckNTSD(ntsdValues[0], allSIDMap)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error checking ntsd: %s", err))
				continue
			}
			nstdMessages = append(nstdMessages, results...)
		}
		if len(nstdMessages) > 0 {
			auditMessages = append(auditMessages, "\x1b[96mAttribute nTSecurityDescriptor:\x1b[0m")
			for _, message := range nstdMessages {
				auditMessages = append(auditMessages, fmt.Sprintf("  | \x1b[93m%s\x1b[0m", message))
			}
		}

		// Check RBCD
		allowedToActOnBehalfOfOtherIdentityValues := entry.GetEqualFoldRawAttributeValues("msDS-AllowedToActOnBehalfOfOtherIdentity")
		rbcdMessages := []string{}
		if len(allowedToActOnBehalfOfOtherIdentityValues) != 0 {
			results, err := sidchecks.CheckRBCD(allowedToActOnBehalfOfOtherIdentityValues[0], allSIDMap)
			if err != nil {
				logger.Warn(fmt.Sprintf("Error checking ntsd: %s", err))
				continue
			}
			rbcdMessages = append(rbcdMessages, results...)
		}
		if len(rbcdMessages) > 0 {
			auditMessages = append(auditMessages, "\x1b[96mAttribute msDS-AllowedToActOnBehalfOfOtherIdentity:\x1b[0m")
			for _, message := range rbcdMessages {
				auditMessages = append(auditMessages, fmt.Sprintf("  | \x1b[93m%s\x1b[0m", message))
			}
		}

		if len(auditMessages) > 0 {
			o.Results[entry.DN] = auditMessages
			logger.Info(fmt.Sprintf("[>] \x1b[94m%s\x1b[0m", entry.DN))
			for _, result := range auditMessages {
				logger.Info(fmt.Sprintf("  | %s", result))
			}
		}
	}

	logger.Info(fmt.Sprintf("Found %d old SID traces", len(o.Results)))
}
