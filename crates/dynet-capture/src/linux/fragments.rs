use std::{env, path::PathBuf};

use super::{DYN_TABLE_ID, OWNER_MARKER};

pub(super) fn path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

pub(super) fn sysctl_fragment_content() -> String {
    format!(
        "{OWNER_MARKER}\n\
         # Installed by dynet apply --auto. Loaded by sysctl tooling, not by \
         writing global sysctl files.\n\
         net.ipv4.ip_forward = 1\n\
         net.ipv4.conf.all.rp_filter = 0\n\
         net.ipv4.conf.default.rp_filter = 0\n\
         net.ipv4.conf.dynet0.rp_filter = 0\n"
    )
}

pub(super) fn rt_tables_fragment_content() -> String {
    format!("{OWNER_MARKER}\n{DYN_TABLE_ID} dynet\n")
}
