rule Win32_Ransomware_Dharma : tc_detection malicious
{
    meta:
        id = "68aCBzNw5nt2Y4PXoIdToQ"
        fingerprint = "d5ff8bc6726c76fb19d436ff5a96de8ff4c4b08b09bb0655800d28a80c14364d"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Dharma ransomware."
        category = "MALWARE"
        malware = "DHARMA"
        malware_type = "RANSOMWARE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "Dharma"
        tc_detection_factor = 5

    strings:

        $file_search = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            8B 45 ?? 50 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 8D 4D ?? 51 8B 55 
            ?? 52 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 
            75 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? 81 7D ?? ?? ?? ?? ?? 76 ?? 8B 
            4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 
            55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D 
            ?? ?? 75 ?? 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 
            8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 
            89 45 ?? 8B 45 ?? 8B E5 5D C3 
        }

        $file_encrypt_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? 8B 45 ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 83 C1 ?? 89 4D ?? C7 45 
            ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8B 45 ?? 33 D2 B9 ?? ?? ?? ?? F7 F1 8B 45 ?? 2B C2 83 E8 ?? 89 45 ?? 8B 
            4D ?? 51 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? 
            ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 05 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 83 ?? ?? 
            ?? ?? 8B 4D ?? 83 E1 ?? 74 ?? 8B 55 ?? 83 E2 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 6A ?? 
            6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 
            ?? 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 89 55 ?? 8B 45 ?? 89 85 ?? ?? ?? 
            ?? 8B 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8B 85 ?? ?? ?? ?? 50 8B 8D 
            ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? 
            83 7D ?? ?? 0F 84 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 
            ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 8B 4D ?? 51 
            E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? 
            ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 8B 45 ?? 50 8B 4D 
            ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 45 ?? 50 8B 4D ?? 51 8B 
            55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 83 7D 
            ?? ?? 75 ?? 8B 4D ?? 3B 4D ?? 73 ?? 8B 45 ?? 33 D2 B9 ?? ?? ?? ?? F7 F1 B8 ?? ?? ?? 
            ?? 2B C2 89 45 ?? 8B 4D ?? 03 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 03 45 ?? 50 8B 4D ?? 51
        }


        $file_encrypt_2 = {
            8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? 03 45 ?? 39 85 ?? ?? ?? ?? 
            74 ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 6A ?? 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 
            83 C4 ?? 8B 95 ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? 
            ?? 83 7D ?? ?? 74 ?? 8B 8D ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 8B 55 ?? 52 8B 45 ?? 50 
            8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 03 55 ?? 89 55 ?? 8B 45 ?? 03 45 ?? 89 
            45 ?? 6A ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 83 C0 ?? 89 45 
            ?? 6A ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 83 C0 ?? 89 45 ?? 
            6A ?? 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 83 C0 ?? 89 
            45 ?? 6A ?? 8D 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 83 C0 ?? 89 45 
            ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 05 ?? ?? 
            ?? ?? 89 45 ?? 6A ?? 8D 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 83 C0 
            ?? 89 45 ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 2B 55 ?? 52 8B 45 ?? 50 8B 8D ?? ?? 
            ?? ?? 51 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 55 ?? 2B 55 ?? 39 95 ?? ?? ?? ?? 74 ?? EB ?? 
            EB ?? 8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? E9 ?? 
            ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 7E ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 8D ?? ?? 
            ?? ?? 51 8B 95 ?? ?? ?? ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 
            8B 55 ?? 52 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 7E ?? 8B 45 ?? 50 8B 4D ?? 51 E8 ?? 
            ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 85 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $enum_shares = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? 8D 45 ?? 
            50 8B 4D ?? 51 6A ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8B 45 ?? 50 8D 4D ?? 51 8B 55 ?? 52 E8 ?? 
            ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 45 ?? 83 C0 ?? 89 45 
            ?? 8B 4D ?? 3B 4D ?? 0F 83 ?? ?? ?? ?? 8B 55 ?? C1 E2 ?? 8B 45 ?? 83 7C 10 ?? ?? 75 
            ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 50 8B 55 ?? 52 8B 45 ?? C1 E0 ?? 8B 4D ?? 8B 54 01 ?? 
            52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 6A ?? 8B 45 ?? 50 8B 4D ?? C1 E1 ?? 8B 55 ?? 
            8B 44 0A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8B 4D ?? 51 8B 55 ?? C1 E2 ?? 8B 45 ?? 
            8B 4C 10 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C1 E2 ?? 8B 45 ?? 8B 4C 10 ?? 83 E1 
            ?? 74 ?? 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? C1 E1 ?? 03 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 
            ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 55 ?? 
            52 E8 ?? ?? ?? ?? 8D 45 ?? 50 8B 4D ?? 51 6A ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 85 C0 0F 
            85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8B 45 ?? 50 8D 
            4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB 
            ?? 8B 45 ?? 83 C0 ?? 89 45 ?? 8B 4D ?? 3B 4D ?? 0F 83 ?? ?? ?? ?? 8B 55 ?? C1 E2 ?? 
            8B 45 ?? 83 7C 10 ?? ?? 75 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 50 8B 55 ?? 52 8B 45 ?? C1 
            E0 ?? 8B 4D ?? 8B 54 01 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 6A ?? 8B 45 ?? 50 
            8B 4D ?? C1 E1 ?? 8B 55 ?? 8B 44 0A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8B 4D ?? 51 
            8B 55 ?? C1 E2 ?? 8B 45 ?? 8B 4C 10 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C1 E2 ?? 
            8B 45 ?? 8B 4C 10 ?? 83 E1 ?? 74 ?? 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? C1 E1 ?? 03 4D 
            ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $file_search and $enum_shares and $file_encrypt_1 and $file_encrypt_2
}
