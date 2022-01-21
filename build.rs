extern crate iced_x86;
extern crate std;
extern crate winapi;

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::Write;

use std::os::raw::c_char;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
};

fn main() {
    let mut file = File::create("resources/syscall_ids").unwrap();

    for (name, addr) in get_ntdll_exports() {
        if name.starts_with("Nt") {
            if let Some(sys_id) = get_syscall_id(addr) {
                file.write_all(format!("define_syscall {}, {}\n", name, sys_id).as_bytes())
                    .unwrap();
            }
        }
    }
}

fn get_syscall_id(function_addr: usize) -> Option<String> {
    let u8s = unsafe { core::slice::from_raw_parts(function_addr as *const u8, 8) };
    let mut decoder = Decoder::with_ip(64, u8s, 0, DecoderOptions::NONE);

    let mut formatter = NasmFormatter::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut output = String::new();

    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        if output.contains("eax") {
            return Some(format!(
                "0x{}",
                output.split_once("eax,")?.1.to_string().replace("h", "")
            ));
        }
    }

    None
}

fn get_ntdll_exports() -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();

    unsafe {
        let module_base = GetModuleHandleA("ntdll.dll\0".as_ptr() as _);

        let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);

        if dos_header.e_magic == 0x5A4D {
            let nt_header =
                (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;

            if (*nt_header).Signature == 0x4550 {
                let export_directory = (module_base as usize
                    + (*nt_header).OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
                        .VirtualAddress as usize)
                    as *mut IMAGE_EXPORT_DIRECTORY;

                let names = core::slice::from_raw_parts(
                    (module_base as usize + (*export_directory).AddressOfNames as usize)
                        as *const u32,
                    (*export_directory).NumberOfNames as _,
                );
                let functions = core::slice::from_raw_parts(
                    (module_base as usize + (*export_directory).AddressOfFunctions as usize)
                        as *const u32,
                    (*export_directory).NumberOfFunctions as _,
                );
                let ordinals = core::slice::from_raw_parts(
                    (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize)
                        as *const u16,
                    (*export_directory).NumberOfNames as _,
                );

                for i in 0..(*export_directory).NumberOfNames {
                    let name = (module_base as usize + names[i as usize] as usize) as *const c_char;

                    if let Ok(name) = CStr::from_ptr(name).to_str() {
                        let ordinal = ordinals[i as usize] as usize;

                        exports.insert(
                            name.to_string(),
                            module_base as usize + functions[ordinal] as usize,
                        );
                    }
                }
            }
        }
    }

    exports
}
