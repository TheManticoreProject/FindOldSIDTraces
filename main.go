package main

import (
	"FindOldSIDTraces/search"
	"FindOldSIDTraces/sidmap"
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/goopts/parser"
)

var (
	// Configuration
	useLdaps   bool
	quiet      bool
	debug      bool
	nocolors   bool
	outputfile string

	// Network
	domainController string
	ldapPort         int
	attribute        string

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "FindOldSIDTraces - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	group_config, err := ap.NewArgumentGroup("Configuration")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_config.NewBoolArgument(&quiet, "-q", "--quiet", false, "Show no information at all.")
		group_config.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")
		group_config.NewBoolArgument(&nocolors, "-nc", "--no-colors", false, "No colors mode.")
		group_config.NewStringArgument(&attribute, "-a", "--attribute", "distinguishedName", false, "Output attribute.")
		group_config.NewStringArgument(&outputfile, "-o", "--output-file", "", false, "Output file to write results to.")
	}

	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	}

	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()

	// Set default port if not specified
	if ldapPort == 0 {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}

	// Validate required arguments
	if domainController == "" {
		fmt.Println("[!] Option -dc <fqdn> is required.")
		ap.Usage()
		os.Exit(1)
	}
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error creating credentials: %s", err))
		return
	}

	allSIDMap := sidmap.AllSIDMap{}
	allSIDMap.PopulateSIDMap(domainController, ldapPort, creds, useLdaps)

	oldSIDTrace := search.OldSIDTrace{}
	oldSIDTrace.SearchOldSIDTraces(&allSIDMap, domainController, ldapPort, creds, useLdaps)

	fmt.Println("[+] Done.")
}
