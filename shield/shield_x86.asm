.code32

// the CriticalSize must be aligned with 4 bytes

// struct:
//   [ebp + 0*4]  VirtualProtect
//   [ebp + 1*4]  WaitForSingleObject
//   [ebp + 2*4]  CriticalAddress
//   [ebp + 3*4]  CriticalSize
//   [ebp + 4*4]  ShelterAddress
//   [ebp + 5*4]  TimerHandle
//   [ebp + 6*4]  CryptoKey

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
  mov {{.RegV.ecx}}, [esp+4]                   {{iji}}
  test {{.RegV.ecx}}, {{.RegV.ecx}}            {{iji}}
  jnz next                                     {{iji}}
  ret 4                                        {{iji}}
 next:

  // save context
  push {{.RegN.ebp}}                           {{iji}} // for save structure pointer
  push {{.RegN.ebx}}                           {{iji}} // for save crypto key
  push {{.RegN.esi}}                           {{iji}} // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.ebp}}, [esp + 4*4]               {{iji}} // save structure pointer
  mov {{.RegN.ebx}}, [{{.RegN.ebp}} + 6*4]     {{iji}} // save crypto key

  // prevent the fixed crypto key
  add {{.RegN.ebx}}, [{{.RegN.ebp}} + 2*4]     {{iji}}
  xor {{.RegN.ebx}}, ecx                       {{iji}}

  // destroy CryptoKey in the stack
  xor {{.RegV.edx}}, {{.RegV.edx}}             {{iji}}
  mov [{{.RegN.ebp}} + 6*4], {{.RegV.edx}}     {{iji}}

  // encrypt return address
  mov {{.RegV.ecx}}, [esp + 3*4]               {{iji}}
  xor {{.RegV.ecx}}, {{.RegN.ebx}}             {{iji}}
  mov [esp + 3*4], {{.RegV.ecx}}               {{iji}}

  // adjust the page protect to PAGE_READWRITE
  push 0x04                                    {{iji}}
  call protect                                 {{iji}}

  // encrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{iji}} // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 3*4]     {{iji}} // set the critical size
  call xor_buf                                 {{iji}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // clear register
  dec {{.RegV.eax}}                            {{iji}} // calculate INFINITE (0xFFFFFFFF)
  mov {{.RegV.edx}}, {{.RegV.eax}}             {{iji}} // set INFINITE
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 5*4]     {{iji}} // set handle of hTimer
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 1*4]     {{iji}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push {{.RegV.edx}}                           {{iji}}
  push {{.RegV.ecx}}                           {{iji}}
  push {{.RegV.eax}}                           {{iji}}

  // encrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{iji}} // get structure pointer
  mov {{.RegV.edx}}, 7*4                       {{iji}} // set the buffer size
  call xor_buf                                 {{iji}}

  // Sleep with WaitForSingleObject
  pop {{.RegV.eax}}                            {{iji}} // get WaitForSingleObject address
  call {{.RegV.eax}}                           {{iji}} // call WaitForSingleObject

  // decrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{iji}} // get structure pointer
  mov {{.RegV.edx}}, 7*4                       {{iji}} // set the buffer size
  call xor_buf                                 {{iji}}

  // decrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{iji}} // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 3*4]     {{iji}} // set the critical size
  call xor_buf                                 {{iji}}

  // recover the page protect to old protect
  push {{.RegN.esi}}                           {{iji}}
  call protect                                 {{iji}}

  // decrypt return address
  mov {{.RegV.ecx}}, [esp + 3*4]               {{iji}}
  xor {{.RegV.ecx}}, {{.RegN.ebx}}             {{iji}}
  mov [esp + 3*4], {{.RegV.ecx}}               {{iji}}

  // restore context
  pop {{.RegN.esi}}                            {{iji}}
  pop {{.RegN.ebx}}                            {{iji}}
  pop {{.RegN.ebp}}                            {{iji}}
  ret 4                                        {{iji}}

xor_buf:
  shr {{.RegV.edx}}, 2                         {{iji}} // calculate the loop count
 loop_xor:
  xor [{{.RegV.ecx}}], {{.RegN.ebx}}           {{iji}} // encrypt data with crypto key
  add {{.RegV.ecx}}, 4                         {{iji}} // add data address
  dec {{.RegV.edx}}                            {{iji}} // update loop count
  jnz loop_xor                                 {{iji}} // check need decrypt again
  ret                                          {{iji}}

protect:
  mov {{.RegV.eax}}, [esp+4]                   {{iji}} // read argument about new protect
  sub esp, 0x04                                {{iji}} // for save old protect
  push esp                                     {{iji}} // lpflOldProtect
  push {{.RegV.eax}}                           {{iji}} // new protect
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 3*4]     {{iji}} // set size of critical
  push {{.RegV.ecx}}                           {{iji}} // push size
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{iji}} // set address of critical
  push {{.RegV.ecx}}                           {{iji}} // push address
  mov {{.RegV.eax}}, [{{.RegN.ebp}}]           {{iji}} // get address of VirtualProtect
  call {{.RegV.eax}}                           {{iji}} // call VirtualProtect
  mov {{.RegN.esi}}, [esp]                     {{iji}} // save old protect
  add esp, 0x04                                {{iji}} // restore stack for old protect
  ret 4                                        {{iji}} // return and release stack
