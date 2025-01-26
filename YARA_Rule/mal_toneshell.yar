rule mal_toneshell
{
	meta:
		version = "1.0"
		first_imported = "2025-01-26"
		last_modified = "2025-01-26"
		sharing = "TLP:CLEAR"
		author = "FatzQatz"
		description = "Detect Toneshell in memory"
		falsepositives= "Unknown"
	strings:
		$h_1 = { C6 04 01 17 }
		$h_2 = { C6 04 10 03 }
		$h_3 = { C6 04 0A 03 }
		$h_4 = { 8A 44 05 FC }
		$h_5 = { 8A 54 15 FC }
	condition:
		all of them
}