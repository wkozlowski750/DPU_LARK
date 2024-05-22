# DPU-LARK

## Intro
This is all source code associated with the thesis work DPU-LARK. A PDF of this thesis is attached in this github repo for further understanding of the project.

### CPU_W_HW_ACCEL
This has the code for hash benches, as well as the verifier side of the remote attestation protocol for a CPU that possesses SHA hardware acceleration. This requires openssl 
v1.1.1 as well as DPDK (data-plane development kit), and uses the meson/ninja build system. See DPDK documentation build instructions.

### CPU_NO_HW_ACCEL
This has the code for the hash benches and ra verifier for a CPU without SHA hardware acceleration. This requires openssl v3.0 and DPDK.

### DPU
This is the source code which was deployed on the Bluefield-2 DPU. This requires the latest version of DOCA to be installed on the DPU. Follow build instructions found in the
DOCA SDK manual to build and deploy applications on the DPU.

The current password for the DPU's on both systems: bluefield2!

### ra_prover_sim
This is the source code which is able to act as many provers (with consecutive MAC addresses) to respond to the verifier. This is deployable on both DPU and CPU, and is 
dependent upon openssl v3.0 and DPDK.

### suv_dpu_lark
This is a fork of the secureArduinoUno repository for the securiyt microvisor. An app has been added called dpu_lark, which is the code required for the microcontroller,
which acts as an intelligent electronic device and a prover to respond to the verifier. This cureently does not interface with ethernet at all.
