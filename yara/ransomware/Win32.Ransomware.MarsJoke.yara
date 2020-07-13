rule Win32_Ransomware_MarsJoke : tc_detection malicious
{
    meta:
        id = "38rG2Rc64qj5P8BfLfVsLu"
        fingerprint = "9b3587c746fd1db9154c1eea75758f7269fdaa8cb331cba14e1929573e19bb61"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects MarsJoke ransomware."
        category = "MALWARE"
        malware = "MARSJOKE"
        malware_type = "RANSOMWARE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "MarsJoke"
        tc_detection_factor = 5

    strings:

        $search_and_encrypt_files = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 8B 45 
            ?? 53 56 89 44 24 ?? 8B 45 ?? 57 89 44 24 ?? 8B 45 ?? BE ?? ?? ?? ?? 33 DB 56 89 44 
            24 ?? 8D 84 24 ?? ?? ?? ?? 8B F9 53 50 89 7C 24 ?? 66 89 9C 24 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 56 8D 84 24 ?? ?? ?? ?? 53 50 66 89 9C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 84 24 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 57 8D 4C 24 ?? 88 5C 24 ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 84 C0 0F 85 ?? ?? ?? ?? 38 5C 24 ?? 0F 85 ?? ?? ?? ?? 8D 84 24 ?? 
            ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 59 59 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 84 
            24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 59 59 BE ?? ?? ?? 
            ?? 56 8D 84 24 ?? ?? ?? ?? 50 FF D7 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 56 FF 
            74 24 ?? FF D7 FF 74 24 ?? 8D 84 24 ?? ?? ?? ?? 50 FF 74 24 ?? E8 ?? ?? ?? ?? 83 C4 
            ?? 84 C0 8D 84 24 ?? ?? ?? ?? 75 ?? 50 FF 15 ?? ?? ?? ?? FF 74 24 ?? E9 ?? ?? ?? ?? 
            6A ?? 50 FF D7 53 68 ?? ?? ?? ?? 6A ?? 53 6A ?? 68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 83 F8 ?? 89 44 24 ?? 75 ?? 56 8D 84 24 ?? ?? ?? ?? 50 FF D7 8D 
            84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 E9 ?? ?? ?? ?? 8D 4C 
            24 ?? 51 50 FF 15 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? FF 74 24 ?? FF 74 24 ?? E8 ?? ?? ?? 
            ?? 89 5C 24 ?? 33 DB 68 ?? ?? ?? ?? 89 44 24 ?? 8D 84 24 ?? ?? ?? ?? 53 50 89 54 24 
            ?? 89 4C 24 ?? 66 89 9C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? FF 74 24 ?? 8D 84 24 
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 59 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 84 
            24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 59 56 8D 84 24 ?? ?? ?? ?? 50 FF 
            D7 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 53 56 6A ?? 53 6A ?? 68 ?? ?? ?? ?? 8D 
            84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 F8 ?? 89 44 24 ?? 75 ?? 56 8D 84 24 ?? ?? 
            ?? ?? 50 FF D7 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? 6A ?? 59 33 C0 66 89 9C 24 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? F3 AB 6A ?? FF 
            74 24 ?? 66 AB 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 8D 8C 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? BF ?? ?? ?? ?? 57 53 FF 15 ?? ?? ?? 
            ?? 57 53 50 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? 0B 44 24 ?? 74 ?? 83 44 
            24 ?? ?? 11 5C 24 ?? EB ?? 89 7C 24 ?? 89 5C 24 ?? BF ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 
            59 50 57 8B 7C 24 ?? 57 E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? 89 47 ?? 8B 44 24 ?? 53 
            89 47 ?? 8D 44 24 ?? 50 68 ?? ?? ?? ?? 57 FF 74 24 ?? C7 47 ?? ?? ?? ?? ?? 88 5C 24 
            ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? C6 44 24 ?? ?? E9 ?? ?? ?? ?? 8B 7C 24 ?? 3B FB 89 
            5C 24 ?? 0F 8C ?? ?? ?? ?? 7F ?? 39 5C 24 ?? 0F 86 ?? ?? ?? ?? 8B 74 24 ?? 83 EE ?? 
            1B FB 89 74 24 ?? 89 7C 24 ?? 89 5C 24 ?? 33 C0 EB ?? 8B 7C 24 ?? 8B 74 24 ?? 39 74 
            24 ?? 75 ?? 3B C7 75 ?? 8B 44 24 ?? 89 44 24 ?? EB ?? C7 44 24 ?? ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 53 FF 74 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 53 8D 44 24 ?? 50 FF 74 24 ?? FF 74 
            24 ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 6A ?? 58 39 44 24 ?? 73 ?? 89 44 24 ?? 39 74 24 
            ?? 75 ?? 33 C0 3B C7 75 ?? 39 5C 24 ?? 7C ?? 7F ?? 83 7C 24 ?? ?? 76 ?? 8B 44 24 ?? 
            83 E0 ?? 74 ?? 8B 4C 24 ?? 2B C8 03 C9 89 4C 24 ?? 6A ?? 68 ?? ?? ?? ?? FF 74 24 ?? 
            53 FF 15 ?? ?? ?? ?? FF 74 24 ?? 89 44 24 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 
            ?? 50 81 EC ?? ?? ?? ?? 6A ?? 59 8B FC FF B4 24 ?? ?? ?? ?? 8D B4 24 ?? ?? ?? ?? FF 
            B4 24 ?? ?? ?? ?? F3 A5 8B B4 24 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 
            53 8D 44 24 ?? 50 FF 74 24 ?? 56 FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 68 ?? ?? ?? ?? 
            53 56 74 ?? FF 15 ?? ?? ?? ?? FF 44 24 ?? 8B 44 24 ?? 89 44 24 ?? 33 C0 3B 44 24 ?? 
            0F 8C ?? ?? ?? ?? 7F ?? 8B 4C 24 ?? 3B 4C 24 ?? 0F 82 ?? ?? ?? ?? EB ?? C6 44 24 ?? 
            ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 74 24 ?? FF 15 ?? ?? ?? ?? 
            FF 74 24 ?? 8B 3D ?? ?? ?? ?? FF D7 FF 74 24 ?? FF D7 56 8D 84 24 ?? ?? ?? ?? 50 FF 
            15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF D6 38 5C 24 ?? 8D 84 24 
            ?? ?? ?? ?? 75 ?? 6A ?? FF 74 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 FF 74 24 ?? 68 ?? ?? 
            ?? ?? 75 ?? E8 ?? ?? ?? ?? 59 59 8D 84 24 ?? ?? ?? ?? 50 FF D6 EB ?? E8 ?? ?? ?? ?? 
            59 59 B0 ?? EB ?? 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 32 C0 8B 8C 24 ?? ?? ?? ?? 
            5F 5E 5B 33 CC E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $remote_connection_2 = {
            55 8D 6C 24 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 45 ?? 
            53 56 57 BE ?? ?? ?? ?? 56 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 56 89 BD ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 83 A5 ?? 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? 
            ?? BE ?? ?? ?? ?? 56 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 FF B5 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? 
            E8 ?? ?? ?? ?? 6A ?? 6A ?? 8B C3 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? 
            ?? 57 E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A 
            ?? 8D 5D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? 
            ?? ?? 56 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 83 A5 ?? ?? ?? ?? ?? BF ?? ?? ?? ?? 57 
            8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 85 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 
            6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 66 83 A5 ?? ?? ?? ?? ?? 57 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? 
            ?? ?? ?? FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A 
            ?? 8D 5D ?? E8 ?? ?? ?? ?? 6A ?? 8D 5D ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 8D 85 
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B C3 
            50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 
            E8 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 59 59 5F 5E 5B 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            59 83 BD ?? ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B 4D ?? 8B 85 ?? 
            ?? ?? ?? 33 CD E8 ?? ?? ?? ?? 83 C5 ?? C9 C3 
        }

        $remote_connection_1 = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 57 8D 85 
            ?? ?? ?? ?? 50 8B F9 8B F2 68 ?? ?? ?? ?? 89 BD ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? FF 15 
            ?? ?? ?? ?? 33 DB 53 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 6A ?? 89 85 ?? ?? ?? ?? 66 C7 85 
            ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 
            88 1F 50 88 1E 66 89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 
            85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 38 9D ?? ?? ?? 
            ?? 59 59 75 ?? 68 ?? ?? ?? ?? C6 07 ?? E8 ?? ?? ?? ?? 59 E9 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 59 89 85 ?? ?? ?? ?? 33 F6 BB ?? ?? ?? ?? 
            56 8D 85 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 FF B5 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 75 ?? 56 53 E8 ?? ?? ?? ?? FF 85 ?? ?? ?? ?? 
            46 83 FE ?? 59 59 7C ?? EB ?? 53 E8 ?? ?? ?? ?? 59 83 BD ?? ?? ?? ?? ?? 7C ?? C6 07 
            ?? 53 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 F6 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 66 
            89 B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 56 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 50 FF 
            B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 56 68 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? FF 15 ?? ?? 
            ?? ?? 3B C6 0F 8E ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 89 B5 ?? ?? ?? ?? 0F 84 ?? 
            ?? ?? ?? 83 A5 ?? ?? ?? ?? ?? 83 A5 ?? ?? ?? ?? ?? 83 8D ?? ?? ?? ?? ?? 56 E8 ?? ?? 
            ?? ?? 59 50 56 8D B5 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 8B C8 85 C9 
            89 8D ?? ?? ?? ?? 7D ?? C6 07 ?? 51 E9 ?? ?? ?? ?? 83 F9 ?? 0F 8C ?? ?? ?? ?? 83 BD 
            ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 66 83 A5 ?? ?? ?? ?? ?? 33 C0 8D BD ?? ?? ?? ?? 66 
            AB 40 3B C8 89 85 ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? 8D 47 ?? E8 ?? ?? ?? ?? 85 C0 59 59 0F 85 ?? ?? ?? ?? 8B 77 ?? 2B 37 
            8D 46 ?? 50 E8 ?? ?? ?? ?? 59 56 6A ?? 50 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 07 8B 
            8D ?? ?? ?? ?? 83 C4 ?? 03 C8 51 8B 4F ?? 2B C8 51 68 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 59 50 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 59 40 50 E8 
            ?? ?? ?? ?? 59 FF B5 ?? ?? ?? ?? 8B F0 6A ?? 56 89 B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 
            C4 ?? FF B5 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 59 56 53 C6 04 06 ?? 
            E8 ?? ?? ?? ?? 83 A5 ?? ?? ?? ?? ?? 83 A5 ?? ?? ?? ?? ?? 83 8D ?? ?? ?? ?? ?? 56 E8 
            ?? ?? ?? ?? 83 C4 ?? 50 56 8D B5 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 F6 
            3B C6 59 59 0F 8C ?? ?? ?? ?? 83 F8 ?? 0F 8C ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 85 
            ?? ?? ?? ?? 83 F8 ?? 7E ?? 48 8D B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 
            B5 ?? ?? ?? ?? 8D 46 ?? E8 ?? ?? ?? ?? 85 C0 59 59 75 ?? 8B 06 8B 8D ?? ?? ?? ?? 03 
            C8 51 8B 4E ?? 2B C8 51 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            83 C6 ?? FF 8D ?? ?? ?? ?? 75 ?? 33 F6 39 B5 ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 59 39 B5 ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 39 B5 ?? 
            ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 83 C7 ?? 3B 85 ?? ?? ?? ?? 0F 8C ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 
            E8 ?? ?? ?? ?? 85 C0 59 59 0F 85 ?? ?? ?? ?? 39 85 ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 59 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 59 59 B0 ?? E9 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 50 53 C6 
            01 ?? E8 ?? ?? ?? ?? 59 39 B5 ?? ?? ?? ?? 59 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            59 39 B5 ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 39 B5 ?? ?? ?? ?? 74 
            ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 8B 85 ?? ?? ?? ?? 53 C6 00 ?? E8 ?? ?? ?? 
            ?? EB ?? 8D 85 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C6 00 ?? EB ?? 0F 
            84 ?? ?? ?? ?? C6 07 ?? FF 15 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 59 59 83 BD ?? ?? ?? 
            ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            FF 15 ?? ?? ?? ?? 32 C0 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? C9 C3 
        }

    condition:
        uint16(0) == 0x5A4D and $search_and_encrypt_files and $remote_connection_1 and $remote_connection_2
}
