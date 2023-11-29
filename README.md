# Spindump patch for EFM

This repository is a clone of the [Spindump project created by Ericcson Reseach](https://github.com/EricssonResearch/spindump).

The patch introduced here extends the EFM support capabilites of Spindump, adding Spin Bit and Delay Bit for TCP. The marking is coherent with the [IETF RFC 9506](https://datatracker.ietf.org/doc/rfc9506/). 

Spindump is now in fact able to compute the RTT metrics for TCP using the techniques mentioned above.

A Linux kernel witch pactes for Spin Bit and Delay Bit is available at [my GitHub repository](https://github.com/MatteoGuarna/linux_l4s_mod_for_passive_measurements).

### EFM implementation over TCP
The implementation for TCP relies on the reserved bits inside the TCP header:


Bit 5 and 6 inside Byte 12 of the TCP header (i.e., the second and third reserved bits) are used to carry on the information required by the algorithm, and will be referred to as EFM1 and EFM2 from now on.

EFM2 carries the flag required by the Spin Bit or the Delay Bit. Furthermore, in order to allow an observer using Spindump to understand whether it's the Spin Bit or Delay Bit that's being used, the SYN and SYNACK packets must be flagges as follows:
- EFM1=1, EFM2=0 -> Spin Bit
- EFM1=0, EFM2=1 -> Delay Bit

If the handshake packets do not carry this marking the normal RTT calculation applies. Please notice that the defalut RTT calculation is the same as in the parent project, and as of october 2023 is flawed and does not always work properly with TCP when reordering and/or losses are in place. Spin Bit and Delay Bit instead do not have this issue and work as expected.
