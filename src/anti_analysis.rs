use std::{collections::HashMap, path::Path, process};

use gethostname::gethostname;
use sysinfo::{ProcessExt, System, SystemExt};
use wmi::{COMLibrary, Variant, WMIConnection};

pub fn detect() {
    let com_con = COMLibrary::new().unwrap().into();

    if is_server_os(com_con) || is_vm_by_wim_temper(com_con) || detect_md5_processes() {
        println!("Detect vm !!\nExit\n");
        process::exit(0);
    }
}

fn is_server_os(com_con: COMLibrary) -> bool {
    let hostname = gethostname();

    let namespace_path = format!("{}\\ROOT\\CIMV2", hostname.to_str().unwrap());
    let wmi_con = match WMIConnection::with_namespace_path(&namespace_path, com_con) {
        Ok(wmi_con) => wmi_con,
        Err(_) => return false,
    };

    let results: Vec<HashMap<String, Variant>> = wmi_con
        .raw_query("SELECT ProductType FROM Win32_OperatingSystem")
        .unwrap();

    for result in results {
        for value in result.values() {
            if *value == Variant::UI4(2) || *value == Variant::UI4(3) {
                return true;
            }
        }
    }

    false
}

fn detect_md5_processes() -> bool {
    let mut system = System::new();
    system.refresh_all();

    for (_, process) in system.processes() {
        if let Some(arg) = process.cmd().get(0) {
            let path = Path::new(arg);

            match path.file_stem() {
                Some(file_name) => {
                    if file_name.len() == 64 {
                        return true;
                    }
                }
                None => (),
            }
        }
    }

    false
}

fn is_vm_by_wim_temper(com_con: COMLibrary) -> bool {
    let wmi_con = WMIConnection::new(com_con).unwrap();

    let results: Vec<HashMap<String, Variant>> = wmi_con
        .raw_query("SELECT * FROM Win32_CacheMemory")
        .unwrap();

    if results.len() < 2 {
        return true;
    }

    false
}
