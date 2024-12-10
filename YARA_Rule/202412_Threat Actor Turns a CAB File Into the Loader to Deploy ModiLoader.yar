rule cab_loader
{

	meta:
		version = "1.0"
		first_imported = "2024-12-10"
		last_modified = "2024-12-10"
		sharing = "TLP:CLEAR"
		source = "https://link.medium.com/g4RTGBrxdPb "
		author = "FatzQatz"
		description = "Detect the suspicious CAB file with the embedded CMD command and PE file"
		hash = "a631e4304cf932de1129cc660fd648125226cfee4059321b4e2048c38b2f9357"
		
	strings:
		$cmd_1 = "extrac32" nocase
		$cmd_2 = "&&"
		$cmd_3 = "%~f0"
		$cmd_4 = "start" nocase
		$pe_1 = "This program must be run under Win32"
		$pe_2 = "This program cannot be run in DOS mode"
		
	condition:
		uint32(0) == 0x4643534D
		and all of ($cmd_*)
		and any of ($pe_*)
}