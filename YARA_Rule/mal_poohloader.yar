rule mal_poohloader
{
	meta:
		version = "1.0"
		first_imported = "2025-01-26"
		last_modified = "2025-01-26"
		sharing = "TLP:CLEAR"
		author = "FatzQatz"
		description = "Detect PoohLoader, a Loader used by Mustang Panda to deploy Toneshell. This Loader utilized Mavinject to inject the shellcode."
		falsepositives= "Unknown"
	strings:
		$s_1 = "C:\\Windows\\SysWOW64\\waitfor.exe" nocase wide
		$s_2 = "c:\\windows\\System32\\regsvr32.exe" nocase wide
		$s_3 = "C:\\Windows\\SysWOW64\\Mavinject.exe" nocase wide
		$s_4 = "DllRegisterServer" nocase
		$s_5 = "INJECTRUNNING" nocase wide
		$hex = {
			8B 45 F8			// mov     eax, [ebp+data_size]
			2B 45 EC			// sub     eax, [ebp+var_14]
			8B 4D EC			// mov     ecx, [ebp+var_14]
			8A 90 ?? ?? ?? ??	// mov     dl, ds:byte_mem1[eax]
			88 91 ?? ?? ?? ??	// mov     mem2[ecx], dl
			8B 45 F8			// mov     eax, [ebp+data_size]
			2B 45 EC			// sub     eax, [ebp+var_14]
			8A 4D E3			// mov     cl, [ebp+var_1D]
			88 88 ?? ?? ?? ??	// mov     ds:byte_mem1[eax], cl
	}
	condition:
		uint16(0) == 0x5A4D
		and (filesize >= 400KB and filesize <= 8MB)
		and (all of ($s_*)
			or (any of ($s_*) and $hex))
}