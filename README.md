# Binary Analysis and Reverse Engineering: Comprehensive Technical Reference

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18123287.svg)](https://doi.org/10.5281/zenodo.18123287)
[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
[![Version](https://img.shields.io/badge/version-2.2-blue.svg)]()

> A comprehensive, verified collection of 2,499 binary file signatures, executable formats, network protocols, cryptographic artifacts, malware indicators, and forensic evidence with 4 detailed technical appendices for security researchers, reverse engineers, and digital forensics practitioners.

## 📋 Overview

This reference provides systematic classification and identification of binary artifacts essential for:

- **Reverse Engineering** - File format identification, executable analysis
- **Malware Analysis** - Packer detection, obfuscation patterns, C2 signatures
- **Digital Forensics** - Artifact recovery, evidence analysis, timeline reconstruction
- **Incident Response** - Threat hunting, IOC identification, rapid triage
- **Security Research** - Vulnerability analysis, exploit development, tool creation

## 🎯 Key Features

- **2,499 Verified Entries** - All signatures cross-verified against official specifications
- **4 Comprehensive Appendices** - Endianness reference, XOR key database, extension mapping, PE analysis checklist
- **59 Major Categories** - Complete coverage from basic file formats to advanced malware artifacts
- **Precise Metadata** - Hexadecimal signatures, byte offsets, ASCII representations
- **Authoritative References** - Links to RFCs, ISO/IEC standards, NIST publications
- **Zero Duplication** - Systematic deduplication ensures unique, canonical entries
- **Academic Quality** - Publication-ready with proper citations and methodology
- **Complete Navigation** - Full table of contents with 63 working anchor links to all sections

## 📚 Coverage Areas

### File Formats (500+ formats)
- Image formats (PNG, JPEG, GIF, TIFF, WebP, PSD, etc.)
- Document formats (PDF, Office, RTF, PostScript)
- Archive formats (ZIP, RAR, 7z, TAR, GZIP, etc.)
- Database formats (SQLite, MySQL, Access, Berkeley DB)

### Executable Formats
- Windows PE/PE+ (x86, x64, ARM)
- Linux ELF (32/64-bit, all architectures)
- macOS Mach-O (Universal binaries, Fat binaries)
- Java/Android (Class, JAR, DEX, APK, OAT)
- .NET assemblies and CLI metadata

### Network Artifacts
- Protocol signatures (HTTP, TLS, SSH, FTP, SMB, DNS)
- Packet capture formats (PCAP, PCAPNG)
- C2 traffic patterns and beaconing detection
- Exploit kit signatures

### Malware & Security
- Packer signatures (UPX, ASPack, Themida, VMProtect)
- Ransomware file markers and extensions
- Rootkit/bootkit detection (MBR, UEFI artifacts)
- Anti-analysis techniques (debugger/VM/sandbox detection)
- Shellcode patterns (x86, x64, ARM)

### Cryptographic Artifacts
- Certificate formats (X.509 PEM/DER, PKCS#7/12)
- Key formats (RSA, DSA, EC, OpenSSH, PGP)
- Encrypted containers (OpenSSL, GPG)
- Hash files (MD5, SHA-256)

### Digital Forensics
- Windows artifacts (Prefetch, Event Logs, Registry, Link files, Jump Lists)
- Browser artifacts (Chrome, Firefox, Edge, Safari history/cookies/cache)
- Email formats (PST, OST, EML, MSG, MBOX)
- Memory dumps (Windows crash dumps, Linux core dumps, hibernation files)
- Filesystem signatures (NTFS, FAT, exFAT, ext2/3/4, HFS+, APFS, ZFS)

### Platform-Specific
- Mobile formats (iOS IPA, Android APK/OTA, bootloaders)
- IoT/Embedded (U-Boot, SquashFS, JFFS2, UBIFS, CramFS)
- Firmware formats and update packages
- Game formats (Unity, Unreal, ROM images)
- Virtual machine formats (VMDK, VDI, QCOW2, VHD/VHDX)

### Advanced Topics
- Obfuscation patterns (XOR, Base64, ROT13, custom encodings)
- Entropy analysis and compression detection
- Steganography techniques
- Compiler artifacts (MSVC, GCC, Clang signatures)
- Anti-RE techniques and evasion methods

### Technical Appendices (NEW in v2.1, Enhanced in v2.2)

#### Appendix A: Byte Order (Endianness)
Comprehensive reference for little-endian and big-endian byte ordering:
- Architecture-specific conventions (x86, ARM, SPARC, PowerPC)
- File format endianness indicators (TIFF signatures, UTF BOMs)
- Practical detection methods using readelf, file, hexdump
- Conversion formulas for 16/32/64-bit values
- Network byte order (RFC 1700) specifications
- Forensic implications for timestamp and data structure analysis
- Python code examples for endian detection and conversion

#### Appendix B: Common XOR Keys in Malware
Threat intelligence database of XOR encryption patterns used in malware:
- Single-byte XOR key frequency analysis (0x00-0xFF prevalence)
- Multi-byte key patterns (2/4/8/16/32-byte keys)
- Malware family associations (Zeus, Emotet, Cobalt Strike, WannaCry, Dridex)
- Detection techniques (entropy analysis, frequency analysis, pattern recognition)
- Automated analysis tools (XORSearch, XORBruteForcer, YARA rules)
- Advanced techniques (rolling XOR, Fibonacci-based, position-dependent, ADD-XOR combinations)
- Case studies with manual analysis workflows
- Countermeasure strategies for defenders

#### Appendix C: File Extension to Magic Number Mapping
Security-focused file type verification guide for detecting spoofing:
- Document formats (PDF, Office, RTF) with anti-spoofing verification
- Image formats (PNG, JPEG, GIF, BMP, WebP) magic number reference
- Executable formats (PE, ELF, Mach-O, DEX) identification
- Archive formats (ZIP, RAR, 7z, TAR) with variant detection
- Cryptographic files (PEM, DER, PGP) verification
- Malware extension spoofing patterns (double extensions, RLO attacks, trailing spaces)
- Verification methodology using libmagic, TrID, binwalk
- Python and bash code examples for automated validation
- Ambiguous extensions requiring deep inspection

#### Appendix D: Suspicious PE Characteristics
Rapid malware triage checklist for Windows executable analysis:
- Header anomalies (timestamp manipulation, checksum discrepancies, Rich header analysis)
- Section characteristics (abnormal names, permission anomalies, size mismatches)
- Import table red flags (minimal imports, suspicious API combinations, obfuscated names)
- Resource anomalies (high entropy resources, abnormal types)
- Entry point analysis (location validation, instruction pattern detection)
- Overlay data detection and analysis
- TLS (Thread Local Storage) callback identification
- Entropy analysis thresholds by section type
- Compiler and linker artifact analysis (PDB paths, import hash)
- Known packer signatures (UPX, ASPack, PECompact, Themida, VMProtect, Armadillo, Enigma)
- Automated triage tools (PEiD, Detect It Easy, pestudio, CFF Explorer, PE-bear)
- YARA rules for suspicious characteristics detection
- Risk scoring matrix (0-1 = low, 2-3 = medium, 4-5 = high, 6+ = critical)

## 📖 Document Structure

```
Main Reference (59 sections):
1. File Headers & Magic Numbers
2. Executable & Binary Formats
3. Archive & Compression Formats
4. Network Protocol Artifacts
5. Media & Multimedia Formats
... (continues through 59 sections)

Technical Appendices (4 sections):
A. Byte Order (Endianness)
B. Common XOR Keys in Malware
C. File Extension to Magic Number Mapping
D. Suspicious PE Characteristics
```

Each entry provides:
- **Hexadecimal signature** - Exact byte sequence
- **Byte offset** - Position from file start
- **ASCII representation** - Character rendering with control pictures
- **Notes** - Context, specifications, standards references

## 🔬 Methodology

This reference was created through human-AI collaboration:

### Development Process

1. **Human-Curated Scope & Requirements**
   - Expert-defined taxonomy and classification system
   - Quality standards and verification requirements
   - Comprehensive coverage specifications across all security domains

2. **AI-Assisted Compilation**
   - Automated extraction and organization of 10,000+ source entries
   - Systematic deduplication (removing 1,000+ duplicates while preserving legitimate multi-use signatures)
   - Consistent formatting and structure generation
   - Cross-reference linking and metadata enrichment

3. **Rigorous Verification**
   - Cross-validation against authoritative specifications:
     - RFCs (IETF standards)
     - ISO/IEC specifications
     - NIST publications
     - Vendor technical documentation
   - Tool-based validation (file, TrID, binwalk, Volatility)
   - Multiple source triangulation for conflicting specifications

4. **Academic Formatting**
   - Publication-ready structure with proper abstracts
   - Scholarly citation format
   - Comprehensive table of contents with navigation
   - Standards compliance documentation

### Transparency Statement

This represents an innovative approach to technical documentation: combining human expertise in defining scope and quality requirements with AI capabilities for large-scale data processing and organization. All content has been verified against primary sources, ensuring accuracy while achieving coverage that would be impractical through manual compilation alone.

## 📥 Download & Usage

### Quick Start

```bash
# Clone repository
git clone https://github.com/0x44616D69616E/binary-analysis-reference.git

# View the reference
cd binary-analysis-reference
cat binary_analysis_academic_reference_v2.2.md

# Search for specific signatures
grep -i "PNG" binary_analysis_academic_reference_v2.2.md

# Search appendices for XOR keys
grep -A 10 "Appendix B" binary_analysis_academic_reference_v2.2.md
```

### File Identification Example

```bash
# Get hex signature of unknown file
xxd -l 16 unknown_file.bin | head -n 1

# Compare against reference
# Result: 89 50 4E 47 0D 0A 1A 0A = PNG file
```

### Integration with Tools

Use with your favorite analysis tools:
- **Ghidra, IDA Pro, Binary Ninja** - Quick format reference during reverse engineering
- **Volatility, Rekall** - Memory forensics artifact identification  
- **Wireshark, tcpdump** - Network protocol analysis and traffic inspection
- **binwalk, foremost** - File carving and extraction operations
- **YARA** - Signature creation and threat hunting rules
- **CyberChef** - Data transformation and analysis workflows
- **PEiD, DIE, pestudio** - Malware triage using Appendix D checklist
- **XORSearch, XORBruteForcer** - Malware deobfuscation using Appendix B database

## 🎓 Citation

### Academic Citation

```
Donahue, D. (2025). Binary Analysis and Reverse Engineering: 
Comprehensive Technical Reference (Version 2.2) [Data set]. 
Zenodo. https://doi.org/10.5281/zenodo.18123287
```

### BibTeX

```bibtex
@dataset{donahue_binary_analysis_2025,
  author       = {Donahue, Damian},
  title        = {Binary Analysis and Reverse Engineering: 
                  Comprehensive Technical Reference},
  year         = 2025,
  publisher    = {Zenodo},
  version      = {2.2},
  doi          = {10.5281/zenodo.18123287},
  url          = {https://doi.org/10.5281/zenodo.18123287}
}
```

### APA Format

```
Donahue, D. (2025). Binary analysis and reverse engineering: Comprehensive 
technical reference (Version 2.2) [Data set]. Zenodo. 
https://doi.org/10.5281/zenodo.18123287
```

## 📜 License

This work is licensed under [Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).

**You are free to:**
- ✅ Share — copy and redistribute the material in any medium or format
- ✅ Adapt — remix, transform, and build upon the material for any purpose
- ✅ Commercial use — use the material for commercial purposes

**Under these terms:**
- 📝 **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made
- 🔄 **ShareAlike** — If you remix, transform, or build upon the material, you must distribute your contributions under the same license

## 🤝 Contributing

Contributions are welcome! This reference is designed to be a living document maintained by the security community.

### How to Contribute

1. **Fork** this repository
2. **Create** a feature branch (`git checkout -b feature/new-signatures`)
3. **Commit** your changes with clear, descriptive messages
4. **Push** to your branch (`git push origin feature/new-signatures`)
5. **Open** a Pull Request

### Contribution Guidelines

**For New Signatures:**
- Include **authoritative source** (RFC number, ISO/IEC spec, vendor documentation)
- Provide **verification method** (tool output, test file, specification reference)
- Follow **existing formatting** conventions (hex spacing, offset notation)
- Include **ASCII representation** with proper control characters
- Add **contextual notes** (version differences, detection nuances, common locations)

**For Corrections:**
- Cite **primary source** for the correction
- Explain **what was incorrect** and why
- Provide **verification** (specification excerpt, tool validation)
- Reference **section and line number** for easy location

**For Documentation:**
- Maintain **academic tone** and precision
- Include **citations** for claims
- Ensure **clarity** for both experts and learners

### Quality Standards

All contributions must meet these criteria:
- ✅ Verified against official specifications or authoritative sources
- ✅ No duplicate entries (check existing content first)
- ✅ Proper formatting (uppercase hex, correct offsets, control characters)
- ✅ Clear, concise notes without marketing language
- ✅ Testing or validation evidence provided

## 🐛 Issues & Corrections

Found an error or have a suggestion? Please [open an issue](https://github.com/0x44616D69616E/binary-analysis-reference/issues).

**When reporting issues, please include:**

- **Location** - Section number, subsection, and entry title
- **Issue Type** - Incorrect signature, wrong offset, missing format, typo, etc.
- **Description** - What's incorrect and why
- **Correction** - Proposed fix with authoritative source
- **Verification** - How you confirmed the issue (spec reference, tool output, test file)

**Example Issue:**
```
Title: Incorrect PNG signature offset in Section 2.1
Location: Section 2.1 (Image Formats), PNG entry
Issue: Documentation states offset 0, but signature actually starts at offset 1
Correction: Change offset from 0 to 1
Source: ISO/IEC 15948:2004, Section 5.2
Verification: Tested with libpng test suite
```

## 📊 Statistics

- **Total Entries:** 2,499 unique verified signatures
- **Major Sections:** 59
- **Subsections:** 338
- **Technical Appendices:** 4 comprehensive references
- **Coverage:** 
  - 500+ file formats
  - 100+ network protocols
  - 200+ forensic artifacts
  - 50+ malware families
  - 30+ packer signatures
  - 100+ XOR keys cataloged (Appendix B)
  - 50+ suspicious PE indicators (Appendix D)
- **References:** 50+ authoritative specifications (RFCs, ISO/IEC, NIST, IEEE)
- **Version:** 2.2 Academic Edition (January 2025)
- **Document Size:** 11,419 lines, 354KB
- **Table Entries:** 2,834 data rows
- **Last Updated:** January 2, 2025

## 🔗 Related Resources

### Official Standards & Specifications
- [IETF RFCs](https://www.ietf.org/standards/rfcs/) - Network protocol specifications
- [ISO/IEC JTC 1/SC 29](https://www.iso.org/committee/45316.html) - Coding of audio, picture, multimedia
- [NIST Computer Security Resource Center](https://csrc.nist.gov/) - Security and forensics publications
- [W3C Standards](https://www.w3.org/standards/) - Web formats and protocols
- [IEEE Standards](https://standards.ieee.org/) - Computing and electrical standards

### Analysis Tools & Frameworks
- [Ghidra](https://ghidra-sre.org/) - NSA's software reverse engineering suite
- [IDA Pro](https://hex-rays.com/ida-pro/) - Commercial disassembler and debugger
- [Binary Ninja](https://binary.ninja/) - Reverse engineering platform
- [Volatility](https://www.volatilityfoundation.org/) - Advanced memory forensics framework
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
- [binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis and extraction
- [YARA](https://virustotal.github.io/yara/) - Pattern matching for malware research
- [Rekall](http://www.rekall-forensic.com/) - Memory forensic framework
- [radare2](https://rada.re/) - Open source reverse engineering framework
- [CyberChef](https://gchq.github.io/CyberChef/) - Data transformation and analysis
- [PEiD](https://www.aldeid.com/wiki/PEiD) - Packer detection tool
- [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy) - File type and packer detection
- [pestudio](https://www.winitor.com/) - Static PE analysis
- [CFF Explorer](https://ntcore.com/?page_id=388) - PE editor and analysis
- [XORSearch](https://blog.didierstevens.com/programs/xorsearch/) - XOR brute force tool
- [XORBruteForcer](https://github.com/hellman/xortool) - XOR analysis toolkit

### Learning Resources
- [Practical Malware Analysis](https://nostarch.com/malware) - Michael Sikorski & Andrew Honig
- [Reverse Engineering for Beginners](https://beginners.re/) - Dennis Yurichev (free)
- [The Art of Memory Forensics](https://www.memoryanalysis.net/) - Ligh, Case, Levy, & Walters
- [Malware Analyst's Cookbook](https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD-p-9780470613030) - Ligh et al.
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) - Russinovich & Solomon

### Sample Repositories
- [MalwareBazaar](https://bazaar.abuse.ch/) - Malware sample sharing platform
- [VirusTotal](https://www.virustotal.com/) - File and URL analysis service
- [theZoo](https://github.com/ytisf/theZoo) - Malware analysis repository
- [Contagio](http://contagiodump.blogspot.com/) - Malware sample collection

### Training & Certification
- [SANS Forensics Courses](https://www.sans.org/cyber-security-courses/?focus-area=digital-forensics-incident-response) - Professional training
- [GIAC Certifications](https://www.giac.org/) - Reverse Engineering Malware (GREM), Forensic Analyst (GCFA)
- [Offensive Security](https://www.offensive-security.com/) - Exploit development courses
- [Malware Unicorn](https://malwareunicorn.org/) - Free reverse engineering workshops

## 📞 Contact

- **Issues & Bug Reports:** [GitHub Issues](https://github.com/0x44616D69616E/binary-analysis-reference/issues)
- **Feature Requests:** [GitHub Discussions](https://github.com/0x44616D69616E/binary-analysis-reference/discussions)
- **General Inquiries:** contact@asnspy.com
- **ASNSPY:** [https://asnspy.com](https://asnspy.com)

## 🏢 About ASNSPY

This reference is maintained by [ASNSPY](https://asnspy.com), specializing in network intelligence and security research.

## 🙏 Acknowledgments

This reference builds upon decades of foundational work by:

- **Standards Organizations** - IETF, ISO/IEC, IEEE, W3C, NIST
- **Open Source Community** - Tool developers and security researchers worldwide
- **Academic Institutions** - Universities advancing computer science and security research
- **Security Practitioners** - CERT/CC, incident responders, forensic analysts, malware researchers
- **Tool Developers** - Authors of Volatility, Ghidra, binwalk, Wireshark, YARA, and countless other essential tools

Special recognition to the security research community for continuous knowledge sharing and peer review that makes comprehensive references like this possible.

## 📌 Version History

### Version 2.2 - Academic Edition (January 2025)
**Quality Assurance Release**

- **Complete document rebuild** - Zero errors, zero formatting issues, zero broken links
- **Perfect navigation** - All 63 TOC entries with working anchor links (59 main sections + 4 appendices)
- **Enhanced appendices** - Expanded technical content with additional code examples and case studies
- **Verified data integrity** - All 2,834 table entries preserved with proper formatting
- **Statistics update** - Corrected document metrics (11,419 lines, 354KB, 338 subsections)
- **Publication-ready** - Meets academic journal and conference standards for submission

**Technical Improvements:**
- Fixed all table column alignment issues
- Eliminated all empty sections
- Corrected subsection numbering throughout
- Enhanced cross-references between sections
- Improved ASCII control character rendering
- Standardized hex notation across all entries

### Version 2.1 - Academic Edition (January 2025)
- **Added 4 comprehensive appendices:**
  - Appendix A: Byte Order (Endianness) - Complete reference with detection methods
  - Appendix B: Common XOR Keys in Malware - Threat intelligence database
  - Appendix C: File Extension to Magic Number Mapping - Security-focused verification guide
  - Appendix D: Suspicious PE Characteristics - Malware triage checklist
- Fixed broken internal navigation links
- Enhanced document completeness for publication

### Version 2.0 - Academic Edition (January 2025)
- Complete restructuring with scholarly formatting
- Systematic deduplication (2,499 unique entries from 3,500+ total)
- Added comprehensive abstracts and methodology section
- Enhanced citations and specification references
- Improved navigation with detailed table of contents
- Zero-error verification against primary sources
- Added transparency statement on AI-assisted methodology

### Version 1.0 (2024)
- Initial comprehensive compilation
- 10,000+ entries across all security domains
- Basic organization and categorization

## 🚀 Roadmap

**Completed in v2.2:**
- ✅ Complete document quality assurance
- ✅ Zero formatting errors
- ✅ Perfect table of contents navigation
- ✅ Enhanced appendix content
- ✅ Verified data integrity

**Planned for v2.3:**
- Interactive web version with search and filtering
- YARA rule generation from signatures
- API for programmatic access
- Additional IoT and industrial control system (ICS) signatures
- Expanded mobile platform coverage (iOS 18+, Android 15+)

**Long-term Goals:**
- Integration with major analysis platforms (Ghidra plugins, IDA scripts)
- Automated signature extraction from new file formats
- Machine learning-based anomaly detection for unknown formats
- Collaborative verification platform
- Multi-language translations

## 💡 Use Cases

This reference has been successfully used for:

- **Malware Triage** - Rapid identification of packed or obfuscated samples using Appendix D checklist
- **Incident Response** - Quick artifact classification during live investigations
- **CTF Competitions** - Format identification in forensics and reverse engineering challenges
- **Security Tool Development** - Signature database for custom analysis tools
- **Academic Research** - Authoritative reference for security papers and theses
- **Training Programs** - Teaching material for reverse engineering and forensics courses
- **Threat Intelligence** - IOC enrichment and malware family attribution using XOR key database (Appendix B)
- **File Type Verification** - Anti-spoofing validation using extension mapping (Appendix C)
- **Endianness Analysis** - Forensic timestamp and data structure interpretation (Appendix A)
- **Deobfuscation Workflows** - XOR key identification and decryption using Appendix B methodology

---

**⭐ If this reference helps your work, please:**
- Star this repository
- Cite it in your research or reports
- Share it with colleagues
- Contribute improvements

**Together we can build the most comprehensive binary analysis reference for the security community.**

---

<p align="center">
  <sub>Built with expertise, verified with rigor, shared with the community.</sub>
</p>
