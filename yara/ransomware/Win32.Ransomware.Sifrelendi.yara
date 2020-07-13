rule Win32_Ransomware_Sifrelendi : tc_detection malicious
{
    meta:
        id = "2HMT1nGQ1ojANKLi9BXvwK"
        fingerprint = "a4cd22ca3ceb24a40645f9c72ffce19cf26a6536c8a1d55f459bb4747977e98f"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Sifrelendi ransomware."
        category = "MALWARE"
        malware = "SIFRELENDI"
        malware_type = "RANSOMWARE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Sifrelendi"
        tc_detection_factor = 5

    strings:

        $search_files = {                        
            E9 ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 
            33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 7E ?? 8D 85 ?? ?? ?? 
            ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 33 C0 5A 59 59 64 89 10 68 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? 
            ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 
            89 20 F6 85 ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 
            ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? 8D 85 ?? ?? ?? ?? 8B 8D ?? 
            ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 EB 
            ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5F 5E 5B 8B E5 5D 
            C3 
        }

        $encrypt_files = {                        
            55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 89 4D ?? 89 55 ?? 89 45 ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 
            FF 30 64 89 20 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B2 ?? A1 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 89 45 ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 33 C9 B2 ?? A1 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B F8 8B 0D ?? ?? ?? ?? 8B 55 ?? 8B C7 E8 ?? ?? ?? ?? 33 C9 B2 
            ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 8B 0D ?? ?? ?? ?? 8B 55 ?? 8B C6 E8 ?? ?? ?? 
            ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8B 45 
            ?? 8B 10 FF 12 50 8B CB 8B 55 ?? 8B C6 E8 ?? ?? ?? ?? 8B C6 8B 10 FF 52 ?? 6A ?? 6A 
            ?? 8B C3 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 12 50 8B 4D ?? 8B D3 8B C7 E8 ?? ?? ?? ?? 8B 
            C7 8B 10 FF 52 ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? 
            E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 8D 45 
            ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 8B 45 ?? E8 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5F 5E 5B 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $search_files
        ) and 
        (
            $encrypt_files
        )
}
