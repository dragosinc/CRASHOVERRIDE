import "pe"
import "hash"

rule dragos_crashoverride_suspicious_export
{
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Export"
		author = "Dragos Inc"

	condition:
		pe.exports("Crash")
}

rule dragos_crashoverride_suspcious
{
meta:
	description = "CRASHOVERRIDE v1 Wiper"
	author = "Dragos Inc"

	strings:
		$s0 = "SYS_BASCON.COM" fullword nocase wide
		$s1 = ".pcmp" fullword nocase wide
		$s2 = ".pcmi" fullword nocase wide
		$s3 = ".pcmt" fullword nocase wide
		$s4 = ".cin" fullword nocase wide

	condition:
		any of ($s*) and pe.exports("Crash")
}


rule dragos_crashoverride_name_search {
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Strings and Export"
		author = "Dragos Inc"

	strings:
		$s0 = "101.dll" fullword nocase wide
		$s1 = "Crash101.dll" fullword nocase wide
		$s2 = "104.dll" fullword nocase wide
		$s3 = "Crash104.dll" fullword nocase wide
		$s4 = "61850.dll" fullword nocase wide
		$s5 = "Crash61850.dll" fullword nocase wide
		$s6 = "OPCClientDemo.dll" fullword nocase wide
		$s7 = "OPC" fullword nocase wide
		$s8 = "CrashOPCClientDemo.dll" fullword nocase wide
		$s9 = "D2MultiCommService.exe" fullword nocase wide
		$s10 = "CrashD2MultiCommService.exe" fullword nocase wide
		$s11 = "61850.exe" fullword nocase wide
		$s12 = "OPC.exe" fullword nocase wide
		$s13 = "haslo.exe" fullword nocase wide
		$s14 = "haslo.dat" fullword nocase wide

	condition:
		any of ($s*) and pe.exports("Crash")
}

rule dragos_crashoverride_hashes {

    meta:
        description = "CRASHOVERRIDE Malware Hashes"
        author = "Dragos Inc"

    condition:
        filesize < 1MB and
        hash.sha1(0, filesize) == "f6c21f8189ced6ae150f9ef2e82a3a57843b587d" or
        hash.sha1(0, filesize) == "cccce62996d578b984984426a024d9b250237533" or
        hash.sha1(0, filesize) == "8e39eca1e48240c01ee570631ae8f0c9a9637187" or
        hash.sha1(0, filesize) == "2cb8230281b86fa944d3043ae906016c8b5984d9" or
        hash.sha1(0, filesize) == "79ca89711cdaedb16b0ccccfdcfbd6aa7e57120a" or
        hash.sha1(0, filesize) == "94488f214b165512d2fc0438a581f5c9e3bd4d4c" or
        hash.sha1(0, filesize) == "5a5fafbc3fec8d36fd57b075ebf34119ba3bff04" or
        hash.sha1(0, filesize) == "b92149f046f00bb69de329b8457d32c24726ee00" or
        hash.sha1(0, filesize) == "b335163e6eb854df5e08e85026b2c3518891eda8"
}

rule dragos_crashoverride_moduleStrings {

	meta:
		description = "IEC-104 Interaction Module Program Strings"
		author = "Dragos Inc"

	strings:
		$s1 = "IEC-104 client: ip=%s; port=%s; ASDU=%u" nocase wide ascii
		$s2 = " MSTR ->> SLV" nocase wide ascii
		$s3 = " MSTR <<- SLV" nocase wide ascii
		$s4 = "Unknown APDU format !!!" nocase wide ascii
		$s5 = "iec104.log" nocase wide ascii

	condition:
		any of ($s*)
}

rule crashoverride_configReader
{
	meta:
		description = "CRASHOVERRIDE v1 Config File Parsing"
		author = "Dragos Inc"
	
	strings:
		$s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
		$s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
		$s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
		$s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }
		
	condition:
		all of them
}

rule crashoverride_weirdMutex
{
	meta:
		description = "Blank mutex creation assoicated with CRASHOVERRIDE"
		author = "Dragos Inc"
	strings:
		$s1 = { 81 ec 08 02 00 00 57 33 ff 57 57 57 ff 15 ?? ?? 40 00 a3 ?? ?? ?? 00 85 c0 }
		$s2 = { 8d 85 ?? ?? ?? ff 50 57 57 6a 2e 57 ff 15 ?? ?? ?? 00 68 ?? ?? 40 00}
	
	condition:
		all of them
}

rule crashoverride_serviceStomper
{
	meta:
		description = "Identify service hollowing and persistence setting"
		author = "Dragos Inc"
	
	strings:
		$s0 = { 33 c9 51 51 51 51 51 51 ?? ?? ?? }
		$s1 = { 6a ff 6a ff 6a ff 50 ff 15 24 ?? 40 00 ff ?? ?? ff 15 20 ?? 40 00 }
	
	condition:
		all of them
}

rule crashoverride_wiperModuleRegistry
{
	meta:
		description = "Registry Wiper functionality assoicated with CRASHOVERRIDE"
		author = "Dragos Inc"
	
	strings:
		$s0 = { 8d 85 a0 ?? ?? ?? 46 50 8d 85 a0 ?? ?? ?? 68 68 0d ?? ?? 50 }
		$s1 = { 6a 02 68 78 0b ?? ?? 6a 02 50 68 b4 0d ?? ?? ff b5 98 ?? ?? ?? ff 15 04 ?? ?? ?? }
		$s2 = { 68 00 02 00 00 8d 85 a0 ?? ?? ?? 50 56 ff b5 9c ?? ?? ?? ff 15 00 ?? ?? ?? 85 c0 }
	
	condition:
		all of them
}

rule crashoverride_wiperFileManipulation
{
	meta:
		description = "File manipulation actions associated with CRASHOVERRIDE wiper"
		author = "Dragos Inc"
	
	strings:
		$s0 = { 6a 00 68 80 00 00 00 6a 03 6a 00 6a 02 8b f9 68 00 00 00 40 57 ff 15 1c ?? ?? ?? 8b d8 }
		$s2 = { 6a 00 50 57 56 53 ff 15 4c ?? ?? ?? 56 }
		
	condition:
		all of them
}

rule crashoverride_socketCreationArtifacts
{
	meta:
		description = "Socket and connection creation functionality"
		author = "Dragos Inc"
	
	strings:
		$s0 = { c7 85 ?? fe ff ff 02 00 00 00 c7 85 ?? fe ff ff 01 00 00 00 c7 85 ?? fe ff ff 06 00 00 00 ff 15 ?? 91 01 10 }
		$s1 = { 6a 04 ?? ?? ?? fe ff ff 8d 85 ?? fe ff ff 50 68 06 10 00 68 ff ff 00 00 57 ff 15 ?? ?? ?? 01 10 }
		
	condition:
		all of them
}

rule crashoverride_finalCountdownToWiper
{
	meta:
		description = "Countdown to wiper module loading"
		author = "Dragos Inc"
	
	strings:
		$s0 = { 68 80 ee 36 00 ff ?? ?? ?? 40 00 68 e8 09 41 00 ff  ?? ?? ?? 40 00 85 c0 }
		$s1 = { 68 fc 09 41 00 50 ff ?? ?? ?? 40 00 85 c0 74 07 6a 00 ff d0 83 c4 04 }
	
	condition:
		all of them
}
