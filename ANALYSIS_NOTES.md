# Keil

The firmware was compiled with the Keil C51 compiler and linker.

## Memory movement
Keil uses a number of helper methods that copy and covert pointers between the major memory areas. That is XDATA, IDATA, and PDATA. In most cases we're moving data from the current flash bank to EXTMEM (XDATA) so it can be utilized between function calls.

See the page on [?C? Methods](https://developer.arm.com/documentation/ka004580/latest) for some details.


## Tools
A listing of external tools used in analysis.

### AT51
AT51 was used to find the locations of common methods from the Keil libraries.
https://github.com/8051Enthusiast/at51

#### Workflow
1. Install the AT51 tools
2. Download the C51 libraries and put them in $AT51_HOME/libs
  * You only need
3. Extract the memory locations
  * ``



