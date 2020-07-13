rule Win32_Ransomware_RansomPlus : tc_detection malicious
{
    meta:
        id = "6DwiesMVYPTgDkIUQdvskl"
        fingerprint = "196932402ebae48079d3f1d8804a15f2b768016e22130c3dcf0daaba79a1c2b5"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects RansomPlus ransomware."
        category = "MALWARE"
        malware = "RANSOMPLUS"
        malware_type = "RANSOMWARE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "RansomPlus"
        tc_detection_factor = 5

    strings:

        $find_files_1_0 = {
            55 8B EC 83 E4 ?? 83 EC ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 EC ?? 
            8B CC 6A ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? C6 01 ?? E8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8B CC 6A ?? 68 ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? 
            ?? ?? ?? C6 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CC 6A ?? 68 ?? ?? ?? ?? C7 41 ?? 
            ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C6 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CC 6A ?? 
            68 ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C6 01 ?? E8 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8B E5 5D C2 
        }

        $find_files_1_1 = {
            6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 55 ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 78 ?? ?? 72 ?? 8B 00 8D 8D ?? ?? ?? ?? 51 50 FF 15 ?? 
            ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B D8 89 9D ?? ?? ?? ?? 83 F9 ?? 72 ?? 8B 95 ?? ?? ?? ?? 
            41 81 F9 ?? ?? ?? ?? 72 ?? F6 C2 ?? 74 ?? E8 ?? ?? ?? ?? 8B 42 ?? 3B C2 72 ?? E8 ?? 
            ?? ?? ?? 2B D0 83 FA ?? 73 ?? E8 ?? ?? ?? ?? 83 FA ?? 76 ?? E8 ?? ?? ?? ?? 8B D0 52 
            E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C6 85 ?? ?? ?? ?? ?? 83 FB ?? 75 ?? 53 FF 15 ?? ?? ?? ?? 32 DB E9 ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? C6 45 ?? ?? 50 53 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? F6 85 ?? ?? ?? 
            ?? ?? 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 
        }

        $find_files_1_2 = {
            8A 10 3A 11 75 ?? 84 D2 74 ?? 8A 50 ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 
            33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            8A 10 3A 11 75 ?? 84 D2 74 ?? 8A 50 ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 
            33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 75 ?? 33 C9 EB 
            ?? 8D 8D ?? ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 51 8D 85 ?? ?? ?? ?? 50 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 55 ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 
            8B CC C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 83 79 ?? ?? 72 ?? 8B 01 EB ?? 8B C1 
            6A ?? C6 00 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 
            45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 75 ?? 33 C9 EB ?? 8D 8D 
            ?? ?? ?? ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 51 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? 8B 95 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 83 FE ?? 0F 43 C2 0F 43 CA 89 85 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 03 C1 83 FE ?? 8B F8 0F 43 DA 33 C9 2B FB 33 F6 3B D8 0F 47 F9 85 
            FF 74 ?? 0F BE 04 33 50 E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 83 C4 ?? 88 04 31 46 3B F7 
            75 ?? 33 C0 89 85 ?? ?? ?? ?? 8B 94 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 80 3A ?? 75 ?? 33 C9 EB ?? 8B CA 8D 
            71 ?? 8A 01 41 84 C0 75 ?? 2B CE 51 52 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 
            8D 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 F9 ?? 0F 
            43 C2 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 C2 03 85 ?? ?? ?? ?? 83 F9 ?? 8B F8 
            0F 43 DA 33 F6 2B FB 3B D8 0F 47 FE 85 FF 74
        }

        $encrypt_files = {
            8A 01 41 84 C0 75 ?? 2B CA C6 85 ?? ?? ?? ?? ?? 33 C0 88 84 05 ?? ?? ?? ?? 40 3D ?? 
            ?? ?? ?? 72 ?? 33 F6 8B C6 33 D2 F7 F1 8A 04 3A 02 C1 30 84 35 ?? ?? ?? ?? 46 81 FE 
            ?? ?? ?? ?? 72 ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 8D 55 ?? 8B F8 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 0F 43 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 
            D8 85 FF 74 ?? 85 DB 74 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 57 68 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 8B F0 8D 85 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 53 56 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 57 E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 
            83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 C4 ?? 83 F8 
            ?? 72 ?? 8B 8D ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 
            41 ?? 3B C1 72 ?? E8 ?? ?? ?? ?? 2B C8 83 F9 ?? 73 ?? E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? 
            E8 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 83 F8 ?? 72 ?? 8B 4D ?? 40 3D 
            ?? ?? ?? ?? 72 ?? F6 C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 41 ?? 3B C1 72 ?? E8 ?? ?? ?? ?? 
            2B C8 83 F9 ?? 73 ?? E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? E8 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 F8 
            ?? 72 ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 41 ?? 3B 
            C1 72 ?? E8 ?? ?? ?? ?? 2B C8 83 F9 ?? 73 ?? E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? E8 ?? ?? 
            ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 
            4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $find_files_1_0 and $find_files_1_1 and $find_files_1_2 and $encrypt_files
}
