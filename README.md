# GiveMeKernel
This repository contains a condensed and optimized proof-of-concept (PoC) exploit for **CVE-2024-35250**. The code is based on Varwara's original release PoC.

> **Disclaimer:**  
> This PoC is for educational and research purposes only. Use it responsibly and only on systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this code.

## Changes and Optimizations

- **Code Condensation:**  
  The code has been refactored to reduce redundancy by combining similar conditional branches and removing repetitive sections.

- **Type and Function Adjustments:**  
  - Corrected type mismatches, especially in string comparisons (e.g., switching from wide-character to ANSI strings in process enumeration).
  - Maintained core functionality with standard Windows API calls and ensured compatibility across various Windows versions.

- **Refined Process Handling:**  
  Optimized memory allocation and API calls for operations like enumerating processes, obtaining kernel module addresses, and writing to virtual memory.

## Prerequisites

- Windows version  10.0.10240 – 10.0.25398


