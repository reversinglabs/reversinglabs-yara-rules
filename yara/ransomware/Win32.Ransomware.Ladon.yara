rule Win32_Ransomware_Ladon : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        description         = "Yara rule that detects Ladon ransomware."
		malware				= "Ladon"
		malware_type		= "Ransomware"
        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Ladon"
        tc_detection_factor = 5

    strings:

        $find_files = {
            F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 
            3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 
            75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 
            83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 50 57 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? FF 75 ?? 8D 85 
            ?? ?? ?? ?? 53 56 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 FF 85 DB 74 ?? 90 8B 45 ?? 8B 
            34 B8 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 66 8B 08 66 3B 0E 75 ?? 66 85 C9 74 ?? 
            66 8B 48 ?? 66 3B 4E ?? 75 ?? 83 C0 ?? 83 C6 ?? 66 85 C9 75 ?? 33 C0 EB ?? 1B C0 83 
            C8 ?? 85 C0 74 ?? 47 3B FB 72 ?? 8B 75 ?? 8B 7D ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 
            15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 75 ?? 33 DB 83 F8 ?? 0F 
            95 C3 FF 15 ?? ?? ?? ?? 5E 8B C3 5B 5F 8B E5 5D C3 
        }
    
        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 FF 75 ?? 33 DB 89 5D ?? E8 ?? ?? ?? ?? 8B F8 83 
            C4 ?? 89 7D ?? 85 FF 0F 84 ?? ?? ?? ?? 83 3F ?? 0F 85 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 
            FF 77 ?? E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? FF 
            77 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? FF 
            77 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? FF 
            77 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? FF 
            77 ?? E8 ?? ?? ?? ?? 8B C8 83 C4 ?? 89 4D ?? 85 C9 0F 84 ?? ?? ?? ?? 83 3E ?? 0F 85 
            ?? ?? ?? ?? 8B 45 ?? 83 38 ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 83 38 ?? 0F 85 ?? ?? ?? ?? 
            8B 45 ?? 83 38 ?? 0F 85 ?? ?? ?? ?? 83 39 ?? 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 70 
            ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? FF 75 ?? 33 FF C7 45 
            ?? ?? ?? ?? ?? 89 5D ?? E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? 83 3E ?? 75 ?? 57 
            68 ?? ?? ?? ?? FF 76 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? FF 70 ?? 68 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 
            ?? 8D 45 ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? 8D 7B ?? A1 ?? 
            ?? ?? ?? 85 C0 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 1D ?? ?? ?? ?? 85 F6 74 ?? 56 E8 
            ?? ?? ?? ?? 83 C4 ?? 8B C7 5F 5E 5B 8B E5 5D C3 FF 76 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 78 ?? 85 FF 74 ?? 8B 47 ?? 89 45
        }

        $encrypt_files_p2 = {
            8B 70 ?? 8D 4E ?? 8A 06 46 84 C0 75 ?? 2B F1 8D 04 75 ?? ?? ?? ?? 50 6A ?? FF 15 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 84 9D ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 0C 75 
            ?? ?? ?? ?? 51 50 8D 46 ?? 50 8B 45 ?? FF 70 ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 3F 
            43 85 FF 75 ?? 68 ?? ?? ?? ?? C7 84 9D ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 
            ?? E8 ?? ?? ?? ?? 8B 7D ?? 8B 77 ?? 8D 4E ?? 8A 06 46 84 C0 75 ?? 2B F1 8D 46 ?? 50 
            6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B C8 89 4D ?? 85 C9 0F 84 ?? ?? ?? ?? 
            8B C6 99 6A ?? 2B C2 D1 F8 6A ?? 89 45 ?? 8D 45 ?? 50 51 6A ?? 56 FF 77 ?? FF 15 ?? 
            ?? ?? ?? 8B 7D ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 57 8B 7D ?? 8B F0 57 56 FF 15 ?? ?? ?? ?? 56 FF 15 
            ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 57 6A ?? FF 15 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 45 ?? FF 70 ?? E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? 
            ?? ?? 8B 7D ?? A1 ?? ?? ?? ?? 85 C0 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? C7 05 ?? ?? ?? 
            ?? ?? ?? ?? ?? 85 FF 74 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 33 F6 85 DB 74 ?? FF B4 B5 ?? 
            ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 46 3B F3 72 ?? 8B 45 ?? 5F 5E 
            5B 8B E5 5D C3 
        }

        $remote_connection = {
            8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 50 68 ?? ?? ?? ?? 68
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B E5 5D C3 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ??
            C6 85 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ??
            ?? 85 C0 0F 88 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8
            ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ??
            50 E8 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ??
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ??
            ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 78 ?? 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ??
            68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4 ??
            85 F6 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 56 E8 ?? ?? ?? ??
            83 C4 ?? 56 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5E 8B E5 5D C3 
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            $remote_connection
        )
}