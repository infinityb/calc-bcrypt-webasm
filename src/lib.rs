use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn bcrypt_hash2(password: &str, cost: i32) -> Result<String, JsError> {
    let msg = format!("bcrypt_hash2({:?}, {:?})", password, cost);
    alert(&msg);
    match bcrypt::hash(password, cost as u32) {
        Ok(s) => Ok(s),
        Err(err) => {
            let msg = format!("{}", err);
            alert(&msg);
            return Err(JsError::new(&msg));
        }
    }
}

#[derive(Debug, Clone)]
enum MyErrorType {
    SomeError,
}

use core::fmt;
impl std::error::Error for MyErrorType {}
impl fmt::Display for MyErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "display implementation becomes the error message")
    }
}

fn internal_api() -> Result<(), MyErrorType> {
    Err(MyErrorType::SomeError)
}

#[wasm_bindgen]
pub fn throwing_function() -> Result<(), JsError> {
    internal_api()?;
    Ok(())
}
