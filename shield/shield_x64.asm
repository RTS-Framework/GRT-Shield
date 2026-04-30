.code64

// notice:
//   if VirtualProtect is zero, skip adjust page protect
//   the CriticalSize must be 8 bytes aligned

// struct:
//   [rbp + 0*8]  VirtualProtect
//   [rbp + 1*8]  WaitForSingleObject
//   [rbp + 2*8]  CriticalAddress
//   [rbp + 3*8]  CriticalSize
//   [rbp + 4*8]  ShelterAddress
//   [rbp + 5*8]  TimerHandle
//   [rbp + 6*8]  CryptoKey

// steps:
//   encrypt return address
//   adjust the critical memory page protect
//   encrypt the critical instructions
//   encrypt stack about structure
//   call WaitForSingleObject
//   decrypt stack about structure
//   decrypt the critical instructions
//   restore the critical memory page protect
//   decrypt return address

entry:
  // check argument is valid
  test rcx, rcx                                {{iji}}
  jnz next                                     {{iji}}
  ret                                          {{iji}}
 next:

  // save context and ensure stack is 16 bytes alignd
  push {{.RegN.rbp}}                           {{iji}} // for save structure pointer
  push {{.RegN.rbx}}                           {{iji}} // for save crypto key
  push {{.RegN.rsi}}                           {{iji}} // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.rbp}}, rcx                       {{iji}} // save structure pointer
  mov {{.RegN.rbx}}, [{{.RegN.rbp}} + 6*8]     {{iji}} // save crypto key

  // prevent the fixed crypto key
  ror {{.RegN.rbx}}, 7                         {{iji}}
  xor {{.RegN.rbx}}, rcx                       {{iji}}
  rol {{.RegN.rbx}}, 13                        {{iji}}
  add {{.RegN.rbx}}, [{{.RegN.rbp}} + 2*8]     {{iji}}
  ror {{.RegN.rbx}}, 4                         {{iji}}

  // destroy CryptoKey in the stack
  xor {{.RegV.rdx}}, {{.RegV.rdx}}             {{iji}}
  mov [{{.RegN.rbp}} + 6*8], {{.RegV.rdx}}     {{iji}}

  // encrypt return address
  mov {{.RegV.rcx}}, [rsp + 3*8]               {{iji}}
  xor {{.RegV.rcx}}, {{.RegN.rbx}}             {{iji}}
  mov [rsp + 3*8], {{.RegV.rcx}}               {{iji}}

  // encrypt address of WaitForSingleObject
  xor [{{.RegN.rbp}} + 1*8], {{.RegN.rbx}}     {{iji}}

  // adjust the page protect to PAGE_READWRITE
  mov r8, 0x04                                 {{iji}}
  call protect                                 {{iji}}

  // decrypt address of WaitForSingleObject
  xor [{{.RegN.rbp}} + 1*8], {{.RegN.rbx}}     {{iji}}

  // encrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 2*8]     {{iji}} // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 3*8]     {{iji}} // set the critical size
  call xor_buf                                 {{iji}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // clear register
  dec {{.RegV.eax}}                            {{iji}} // calculate INFINITE (0xFFFFFFFF)
  mov edx, {{.RegV.eax}}                       {{iji}} // set INFINITE
  mov rcx, [{{.RegN.rbp}} + 5*8]               {{iji}} // set handle of hTimer
  mov rax, [{{.RegN.rbp}} + 1*8]               {{iji}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push rax                                     {{iji}}
  push rcx                                     {{iji}}
  push rdx                                     {{iji}}

  // encrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{iji}} // get structure pointer
  mov {{.RegV.rdx}}, 7*8                       {{iji}} // set the buffer size
  call xor_buf                                 {{iji}}

  // restore argument about WaitForSingleObject
  pop rdx                                      {{iji}}
  pop rcx                                      {{iji}}
  pop rax                                      {{iji}}

  // Sleep with WaitForSingleObject
  sub rsp, 0x20                                {{iji}} // reserve stack for call convention
  call rax                                     {{iji}} // call WaitForSingleObject
  add rsp, 0x20                                {{iji}} // restore stack for call convention

  // decrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{iji}} // get structure pointer
  mov {{.RegV.rdx}}, 7*8                       {{iji}} // set the buffer size
  call xor_buf                                 {{iji}}

  // decrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 2*8]     {{iji}} // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 3*8]     {{iji}} // set the critical size
  call xor_buf                                 {{iji}}

  // recover the page protect to old protect
  mov r8, {{.RegN.rsi}}                        {{iji}}
  call protect                                 {{iji}}

  // decrypt return address
  mov {{.RegV.rcx}}, [rsp + 3*8]               {{iji}}
  xor {{.RegV.rcx}}, {{.RegN.rbx}}             {{iji}}
  mov [rsp + 3*8], {{.RegV.rcx}}               {{iji}}

  // restore context
  pop {{.RegN.rsi}}                            {{iji}}
  pop {{.RegN.rbx}}                            {{iji}}
  pop {{.RegN.rbp}}                            {{iji}}
  ret                                          {{iji}}

xor_buf:
  shr {{.RegV.rdx}}, 3                         {{iji}} // calculate the loop count
 loop_xor:
  xor [{{.RegV.rcx}}], {{.RegN.rbx}}           {{iji}} // encrypt data with crypto key
  add {{.RegV.rcx}}, 8                         {{iji}} // add data address
  dec {{.RegV.rdx}}                            {{iji}} // update loop count
  jnz loop_xor                                 {{iji}} // check need decrypt again
  ret                                          {{iji}}

protect:
  // check VirtualProtect is zero
  mov {{.RegV.rax}}, [{{.RegN.rbp}}]           {{iji}}
  test {{.RegV.rax}}, {{.RegV.rax}}            {{iji}}
  jnz next_vp                                  {{iji}}
  ret                                          {{iji}}
 next_vp:
  xor {{.RegV.rax}}, {{.RegV.rax}}             {{iji}} // clear register about VirtualProtect
  push {{.RegN.rdi}}                           {{iji}} // save non-volatile register
  mov {{.RegN.rdi}}, [{{.RegN.rbp}}]           {{iji}} // get address of VirtualProtect
  xor [{{.RegN.rbp}}], {{.RegN.rbx}}           {{iji}} // encrypt address of VirtualProtect
  mov rcx, [{{.RegN.rbp}} + 2*8]               {{iji}} // set address of critical
  mov rdx, [{{.RegN.rbp}} + 3*8]               {{iji}} // set size of critical
  sub rsp, 0x08                                {{iji}} // for save old protect
  mov r9,  rsp                                 {{iji}} // lpflOldProtect
  sub rsp, 0x28                                {{iji}} // reserve stack for call convention
  call {{.RegN.rdi}}                           {{iji}} // call VirtualProtect
  add rsp, 0x28                                {{iji}} // restore stack for call convention
  mov {{.RegN.rsi}}, [rsp]                     {{iji}} // save old protect
  add rsp, 0x08                                {{iji}} // restore stack for old protect
  xor [{{.RegN.rbp}}], {{.RegN.rbx}}           {{iji}} // decrypt address of VirtualProtect
  pop {{.RegN.rdi}}                            {{iji}} // restore non-volatile register
  ret                                          {{iji}}
