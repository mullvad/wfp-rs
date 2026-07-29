use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt};

/// Convert `s` to a null-terminated UTF-16 string
pub fn string_to_null_terminated_utf16<T: FromIterator<u16>>(s: impl AsRef<OsStr>) -> T {
    s.as_ref().encode_wide().chain(iter::once(0u16)).collect()
}

/// Convert `s`, a null-terminated UTF-16 string, to an owned string.
/// Returns `None` if `s` is null.
///
/// Unpaired surrogates are preserved, so this never fails.
///
/// # Safety
///
/// If non-null, `s` must be null-terminated.
pub unsafe fn null_terminated_utf16_to_os_string(s: *const u16) -> Option<OsString> {
    if s.is_null() {
        return None;
    }
    // SAFETY: `s` is null-terminated, per the safety requirements
    let len = unsafe { wcslen(s) };
    // SAFETY: `s` points to at least `len` valid u16s
    let slice = unsafe { std::slice::from_raw_parts(s, len) };
    Some(OsString::from_wide(slice))
}

/// Retrieve the length of `s`, a null-terminated UTF-16 string.
///
/// # Safety
///
/// `s` must be null-terminated.
unsafe fn wcslen(s: *const u16) -> usize {
    let mut current = s;
    while unsafe { std::ptr::read_unaligned(current) } != 0 {
        current = unsafe { current.add(1) };
    }
    usize::try_from(unsafe { current.offset_from(s) }).unwrap()
}
