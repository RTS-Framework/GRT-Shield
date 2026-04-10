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
  mov {{.RegV.ecx}}, [esp+4]                   {{igi}}
  test {{.RegV.ecx}}, {{.RegV.ecx}}            {{igi}}
  jnz next                                     {{igi}}
  ret 4                                        {{igi}}
 next:

  // save context
  push {{.RegN.ebp}}                           {{igi}} // for save structure pointer
  push {{.RegN.ebx}}                           {{igi}} // for save crypto key
  push {{.RegN.esi}}                           {{igi}} // for save the memory page old protect

  // save fields to non-volatile registers
  mov {{.RegN.ebp}}, [esp + 4*4]               {{igi}} // save structure pointer
  mov {{.RegN.ebx}}, [{{.RegN.ebp}} + 6*4]     {{igi}} // save crypto key

  // destroy CryptoKey in the stack
  xor {{.RegV.edx}}, {{.RegV.edx}}             {{igi}}
  mov [{{.RegN.ebp}} + 6*4], {{.RegV.edx}}     {{igi}}

  // encrypt return address
  mov {{.RegV.ecx}}, [esp + 3*4]               {{igi}}
  xor {{.RegV.ecx}}, {{.RegN.ebx}}             {{igi}}
  mov [esp + 3*4], {{.RegV.ecx}}               {{igi}}

  // encrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{igi}} // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 3*4]     {{igi}} // set the critical size
  call xor_buf                                 {{igi}}

  // adjust the page protect to PAGE_READWRITE
  push 0x04                                    {{igi}}
  call protect                                 {{igi}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{igi}} // clear register
  dec {{.RegV.eax}}                            {{igi}} // calcualte 0xFFFFFFFF
  mov edx, {{.RegV.eax}}                       {{igi}} // set INFINITE
  mov ecx, [{{.RegN.ebp}} + 5*4]               {{igi}} // set handle of hTimer
  mov eax, [{{.RegN.ebp}} + 1*4]               {{igi}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push edx                                     {{igi}}
  push ecx                                     {{igi}}
  push eax                                     {{igi}}

  // encrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{igi}} // get structure pointer
  mov {{.RegV.edx}}, 7*4                       {{igi}} // set the buffer size
  call xor_buf                                 {{igi}}

  // Sleep with WaitForSingleObject
  pop eax                                      {{igi}} // get WaitForSingleObject address
  call eax                                     {{igi}} // call WaitForSingleObject

  // decrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{igi}} // get structure pointer
  mov {{.RegV.edx}}, 7*4                       {{igi}} // set the buffer size
  call xor_buf                                 {{igi}}

  // recover the page protect to old protect
  push {{.RegN.esi}}                           {{igi}}
  call protect                                 {{igi}}

  // decrypt the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{igi}} // get critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 3*4]     {{igi}} // set the critical size
  call xor_buf                                 {{igi}}

  // decrypt return address
  mov {{.RegV.ecx}}, [esp + 3*4]               {{igi}}
  xor {{.RegV.ecx}}, {{.RegN.ebx}}             {{igi}}
  mov [esp + 3*4], {{.RegV.ecx}}               {{igi}}

  // restore context
  pop {{.RegN.esi}}                            {{igi}}
  pop {{.RegN.ebx}}                            {{igi}}
  pop {{.RegN.ebp}}                            {{igi}}
  ret 4                                        {{igi}}

xor_buf:
  shr {{.RegV.edx}}, 2                         {{igi}} // calculate the loop count
 loop_xor:
  xor [{{.RegV.ecx}}], {{.RegN.ebx}}           {{igi}} // encrypt 8 bytes with xor
  add {{.RegV.ecx}}, 4                         {{igi}} // add data address
  dec {{.RegV.edx}}                            {{igi}} // update loop count
  jnz loop_xor                                 {{igi}} // check need decrypt again
  ret                                          {{igi}}

protect:
  mov {{.RegV.eax}}, [esp+4]                   {{igi}} // read argument about new protect
  sub esp, 0x04                                {{igi}} // for save old protect
  push esp                                     {{igi}} // lpflOldProtect
  push {{.RegV.eax}}                           {{igi}} // new protect
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 3*4]     {{igi}} // set size of critical
  push {{.RegV.ecx}}                           {{igi}} // push size
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 2*4]     {{igi}} // set address of critical
  push {{.RegV.ecx}}                           {{igi}} // push address
  mov {{.RegV.eax}}, [{{.RegN.ebp}}]           {{igi}} // get address of VirtualProtect
  call {{.RegV.eax}}                           {{igi}} // call VirtualProtect
  mov {{.RegN.esi}}, [esp]                     {{igi}} // save old protect
  add esp, 0x04                                {{igi}} // restore stack for old protect
  ret 4                                        {{igi}} // return and release stack
