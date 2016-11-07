# libife

This library enables userspace program to manipulate IFE encapsulation packets.

### IFE encapsulation
IFE is a layer-2 encapsulation protocol that allows adding arbitrary metadata
in the form of TLV (Type-Length-Value) alongside the packet data. For more
information regarding the IFE encapsulation protocol, please refer to the 
[RFC][1].

Currently, IFE packets can be encapsulated by kernel using the tc-ife and
tc-sample actions, and this library allows userspace programs to extract the
metadata from the packets.

The tc-ife is supported from kernel-4.6 and tc-sample is planned to be supported
from kernel-4.10

### Basic Usage
The basic usage is presented in the `testprog/testprog.c` source file. This
program opens a tap device, reads packet from it and tries to decode the packets
using the ife library. 

### Current Support
Currently, the package supports only IFE packet decoding and packet encoding is
not yet supported.

### Further Resources
1. man tc-ife
2. man tc-sample
2. [IFE RFC][1].

[1]: https://tools.ietf.org/html/draft-ietf-forces-interfelfb-04
