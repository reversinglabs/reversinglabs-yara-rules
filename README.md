# ReversingLabs YARA Rules
Welcome to the official ReversingLabs YARA rules repository! The repository will be updated continuously, as we develop rules for new threats, and after their quality has been proven through testing in our cloud and other environments.

These rules have been written by our threat analysts, for threat hunters, incident responders, security analysts, and other defenders that could benefit from deploying high-quality threat detection YARA rules in their environment.

Our detection rules, as opposed to hunting rules, need to satisfy certain criteria to be eligible for deployment, namely:
* be as precise as possible, without losing detection quality
* aim to provide zero false-positive detections

In order for the rules to be easy to understand and maintain, we adopted the following set of goals:
* clearly named byte patterns
* readable and transparent conditions
* match unique malware functionality
* prefer code byte patterns over strings

To ensure the quality of our rules, we continuously and extensively test them in our cloud, on over 10B (and rising) unique binaries. Rules are evaluated on every layer to detect threats within layered objects, such as packed PE files, documents, and archives, among other things.

# Prerequisites
To successfully run the entire YARA rule set, you must have:
* YARA version >= 3.2.0
* PE and ELF modules enabled

(or any other security solution compliant with the requirements).

# Deployment
To start using our rules, just clone this repository, and start experimenting on your data sets. YARA rules found in this repository can be used in various environments, and the simplest setup is to use them through the standalone YARA executable, which can be found in the [official YARA repository](https://github.com/VirusTotal/yara). The rules can also be deployed in a large number of modern security solutions that offer YARA integration, such as YARA-enabled sandboxes, and other file analysis frameworks. However, to get the best results, it is advisable to use the rules through ReversingLabs’ Titanium Platform which offers native integration of these rules into its classification pipeline.

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Acknowledgements
Thanks go to all the people who actively participate in the development of the YARA engine - without you, these rules would not be possible. Also, we’d like to thank everyone who participates in the YARA community, because you evolve the way YARA is used, improve how rules should be written, and are what makes our work worthwhile.