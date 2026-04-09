.code64

// the CriticalSize must be 8 bytes aligned

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
//   encrypt the critical instructions
//   adjust the memory page protect
//   encrypt stack about structure
//   call WaitForSingleObject
//   decrypt stack about structure
//   restore the memory page protect
//   decrypt the critical instructions
//   decrypt return address

entry:
  // check argument is valid
  test rcx, rcx                                {{igi}}
  jnz next                                     {{igi}}
  ret                                          {{igi}}
 next:

  // ensure stack is 16 bytes aligned
  push rbp                                     {{igi}}
  mov rbp, rsp                                 {{igi}}
  and rsp, 0xFFFFFFFFFFFFFFF0                  {{igi}}
  push rbp                                     {{igi}}

  // save context
  push {{.RegN.rbp}}                           {{igi}} // for save structure pointer
  push {{.RegN.rbx}}                           {{igi}} // for save crypto key
  push {{.RegN.rsi}}                           {{igi}} // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.rbp}}, rcx                       {{igi}} // save structure pointer
  mov {{.RegN.rbx}}, [{{.RegN.rbp}} + 6*8]     {{igi}} // save crypto key

  // encrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]               {{igi}}
  xor {{.RegV.rcx}}, {{.RegN.rbx}}             {{igi}}
  mov [rsp + 2*8], {{.RegV.rcx}}               {{igi}}

  // encrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 2*8]     {{igi}} // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 3*8]     {{igi}} // set the critical size
  call xor_buf                                 {{igi}}

  // adjust the page protect to PAGE_READWRITE
  mov r8, 0x04                                 {{igi}}
  call protect                                 {{igi}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{igi}} // clear register
  dec {{.RegV.eax}}                            {{igi}} // calcualte 0xFFFFFFFF
  mov edx, {{.RegV.eax}}                       {{igi}} // set INFINITE
  mov rcx, [{{.RegN.rbp}} + 5*8]               {{igi}} // set handle of hTimer
  mov rax, [{{.RegN.rbp}} + 1*8]               {{igi}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push rax                                     {{igi}}
  push rcx                                     {{igi}}
  push rdx                                     {{igi}}

  // encrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{igi}} // get structure pointer
  mov {{.RegV.rdx}}, 6*8                       {{igi}} // set the buffer size
  call xor_buf                                 {{igi}}

  // restore argument about WaitForSingleObject
  pop rdx                                      {{igi}}
  pop rcx                                      {{igi}}
  pop rax                                      {{igi}}

  // Sleep with WaitForSingleObject
  sub rsp, 0x20                                {{igi}} // reserve stack for call convention
  call rax                                     {{igi}} // call WaitForSingleObject
  add rsp, 0x20                                {{igi}} // restore stack for call convention

  // decrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{igi}} // get structure pointer
  mov {{.RegV.rdx}}, 6*8                       {{igi}} // set the buffer size
  call xor_buf                                 {{igi}}

  // recover the page protect to old protect
  mov r8, {{.RegN.rsi}}                        {{igi}}
  call protect                                 {{igi}}

  // decrypt the critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 2*8]     {{igi}} // get critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 3*8]     {{igi}} // set the critical size
  call xor_buf                                 {{igi}}

  // decrypt return address
  mov {{.RegV.rcx}}, [rsp + 2*8]               {{igi}}
  xor {{.RegV.rcx}}, {{.RegN.rbx}}             {{igi}}
  mov [rsp + 2*8], {{.RegV.rcx}}               {{igi}}

  // restore context
  pop {{.RegN.rsi}}                            {{igi}}
  pop {{.RegN.rbx}}                            {{igi}}
  pop {{.RegN.rbp}}                            {{igi}}

  // restore stack and rbp
  pop rbp                                      {{igi}}
  mov rsp, rbp                                 {{igi}}
  pop rbp                                      {{igi}}
  ret                                          {{igi}}

xor_buf:
  shr {{.RegV.rdx}}, 3                         {{igi}} // calculate the loop count
 loop_xor:
  xor [{{.RegV.rcx}}], {{.RegN.rbx}}           {{igi}} // encrypt 8 bytes with xor
  add {{.RegV.rcx}}, 8                         {{igi}} // add data address
  dec {{.RegV.rdx}}                            {{igi}} // update loop count
  jnz loop_xor                                 {{igi}} // check need decrypt again
  ret                                          {{igi}}

protect:
  sub rsp, 0x08                                {{igi}} // for save old protect
  mov rax, [{{.RegN.rbp}}]                     {{igi}} // get address of VirtualProtect
  mov rcx, [{{.RegN.rbp}} + 2*8]               {{igi}} // set address of critical
  mov rdx, [{{.RegN.rbp}} + 3*8]               {{igi}} // set size of critical
  mov r9,  rsp                                 {{igi}} // lpflOldProtect
  sub rsp, 0x20                                {{igi}} // reserve stack for call convention
  call rax                                     {{igi}} // call VirtualProtect
  add rsp, 0x20                                {{igi}} // restore stack for call convention
  mov {{.RegN.rsi}}, [rsp]                     {{igi}} // save old protect
  add rsp, 0x08                                {{igi}} // restore stack for old protect
  ret                                          {{igi}}
