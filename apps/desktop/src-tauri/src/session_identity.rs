pub fn generate_secret() -> Result<[u8; 32], String> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| format!("Falha ao gerar identidade do evento: {error}"))?;
    Ok(secret)
}

#[cfg(windows)]
pub fn protect(secret: &[u8; 32]) -> Result<Vec<u8>, String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN},
        Foundation::LocalFree,
    };
    let input = CRYPT_INTEGER_BLOB { cbData: secret.len() as u32, pbData: secret.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    let ok = unsafe { CryptProtectData(&input, null(), null(), null_mut(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output) };
    if ok == 0 { return Err("O Windows não conseguiu proteger a chave do evento.".into()); }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut core::ffi::c_void) };
    Ok(bytes)
}

#[cfg(windows)]
pub fn unprotect(ciphertext: &[u8]) -> Result<[u8; 32], String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN},
        Foundation::LocalFree,
    };
    let input = CRYPT_INTEGER_BLOB { cbData: ciphertext.len() as u32, pbData: ciphertext.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    let ok = unsafe { CryptUnprotectData(&input, null_mut(), null(), null_mut(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output) };
    if ok == 0 || output.cbData != 32 { return Err("A identidade protegida do evento não pôde ser aberta neste usuário do Windows.".into()); }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(unsafe { std::slice::from_raw_parts(output.pbData, 32) });
    unsafe { LocalFree(output.pbData as *mut core::ffi::c_void) };
    Ok(secret)
}

#[cfg(not(windows))]
pub fn protect(_secret: &[u8; 32]) -> Result<Vec<u8>, String> {
    Err("A proteção da identidade do evento exige Windows.".into())
}

#[cfg(not(windows))]
pub fn unprotect(_ciphertext: &[u8]) -> Result<[u8; 32], String> {
    Err("A proteção da identidade do evento exige Windows.".into())
}
