# 8051 Analysis Scripts for Keil compiler

## Overview
A collection of Java scripts to aide in the decompilation of the Keil compiler/linker Firmware


## Adding Scripts to Ghidra
1. Open the CodeBrowser Tool or an Existing Workspace
2. Open the Script Manager pane 
  * Window -> Script Manager
  * or, use the green "play" button
3. Click on Manage Script Directories
  * Looks like a list icon
4. Click the add button
5. Navigate to the $REPO_ROOT/ghidra_scripts directory
6. Click OK

## Importing Firmware to Ghidra

I will gloss over all of the documented parts of how to use Ghidra and import files. I will focus on the special steps to get this file imported properly to use with the tools.

1. Back up the processor language files located in $GHIDRA_HOME/Ghidra/Processors/8051/data/languages
2. Copy the files from $REPO_ROOT/Ghidra/Processors/8051/data/languages to $GHIDRA_HOME/Ghidra/Processors/8051/data/languages
3. Open Ghidra and create a new Project
4. Import a file and select the firmware file
5. Change the follwing import settings
  * Format: Raw Binary
  * Language: 8051:BE:16:rtk:Keil (Use Keil to search in the selection box)
  * Options
    * Block Name: CODE
    * Base Address: CODE: 0
    * File Offset: 0x2
    * Length: 0x3ffe
    * Check boxes checked
6. Import the BANKED memory using `LoadBankedMemoryForRTL.java`
  1. See adding Scripts
  2. Select the script 
  3. Select the same firmware file
  4. Click OK
  5. BANK01 - BANKnn should now be visible
7. Import the AT51 Symbols
  * See AT51 Section in [ANALYSIS_NOTES.md](ANALYSIS_NOTES.md)