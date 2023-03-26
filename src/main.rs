use kobold::prelude::*;
use kobold::Mountable;
use wasm_bindgen::prelude::*;
use web_sys::HtmlInputElement;
use std::str;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn bcrypt_hash(password: &str, cost: i32) -> Result<String, JsError> {
    match bcrypt::hash(password, cost as u32) {
        Ok(s) => Ok(s),
        Err(err) => {
            let msg = format!("{}", err);
            log(&msg);
            return Err(JsError::new(&msg));
        }
    }
}

#[wasm_bindgen]
pub fn bcrypt_hash_dom_render(password: &str, cost: i32) -> Result<JsValue, JsError> {
    let s = match bcrypt::hash(password, cost as u32) {
        Ok(s) => s,
        Err(err) => {
            let msg = format!("{}", err);
            log(&msg);
            return Err(JsError::new(&msg));
        }
    };

    let v = view! { <pre>{ s }</pre> };
    Ok(v.build().js().clone())
}

use kobold::prelude::*;

#[derive(Clone, Eq, PartialEq)]
struct BcryptorStateInput {
    cost: u32,
    value: String,
    salt: String,
    //salt_parsed: [u8; 16],
}

impl BcryptorStateInput {
    fn hash(&self) -> Result<String, ()> {
        let salt_parsed = compute_salt(&self.salt)?;
        let v = bcrypt::hash_with_salt(&self.value, self.cost, salt_parsed)
            .map_err(|_| ())
            ?
            .to_string();

        Ok(v)
    }

    fn from(cost: u32, value: &str, salt: &str) -> BcryptorStateInput {
        let mut out = BcryptorStateInput {
            cost,
            value: value.to_string(),
            salt: salt.to_string(),
        };
        
        out
    }
}

struct BcryptorState {
    current: BcryptorStateInput,
    last_computed: BcryptorStateInput,
    last_result: String,
    currently_valid: bool,
}

impl BcryptorState {
    fn refresh(&mut self) {
        if self.last_computed != self.current {
            if let Ok(v) = self.current.hash() {
                self.last_result = v;
                self.last_computed = self.current.clone();
                self.currently_valid = true;
            } else {
                self.currently_valid = false;
            }
        }
    }


    fn new() -> BcryptorState {
        let mut out = BcryptorState {
            current: BcryptorStateInput {
                cost: 4,
                value: "".to_string(),
                salt: "".to_string(),
            },
            last_computed: BcryptorStateInput {
                cost: 0xFFFF_FFFF, // nonsense to force recomputation
                value: "".to_string(),
                salt: "".to_string(),
            },
            last_result: "".to_string(),
            currently_valid: true,
        };

        if out.current.value.is_empty() {
            let mut buf: [u8; 32] = Default::default();
            let mut salt_parsed: [u8; 16] = Default::default();
            getrandom::getrandom(&mut salt_parsed[..]);
            out.current.salt = hex(&mut buf, &salt_parsed[..]).unwrap().to_string();
        }

        out.refresh();
        out
    }
}

fn compute_salt(s: &str) -> Result<[u8; 16], ()> {
    let mut salt: [u8; 16] = [0; 16];
    
    if s.as_bytes().len() == 16 {
        salt.copy_from_slice(s.as_bytes());
        return Ok(salt);
    }

    if s.as_bytes().len() == 32 {
        if let Ok(v) = dehex_fixed_size(s, &mut salt[..]) {
            if v.len() == 16 {
                return Ok(salt);
            }
        }
    }
    return Err(());
}

#[component]
fn Bcryptor() -> impl View {
    stateful(BcryptorState::new , |data| {
        bind! {
            data:
            let onkeyup_value = move |e: KeyboardEvent<HtmlInputElement>| {
                data.current.value = e.target().value();
                data.refresh();
            };
            let onkeyup_salt = move |e: KeyboardEvent<HtmlInputElement>| {
                data.current.salt = e.target().value();
                data.refresh();
            };
            let onchange_cost = move |e: kobold::event::Event<HtmlInputElement, web_sys::Event>| {
                data.current.cost = e.target().value().parse().unwrap();
                data.refresh();
            };
        }

        let salt_style;
        if data.currently_valid {
            salt_style = "background:lime";
        } else {
            salt_style = "background:pink";
        }
        view! {
            <div class="window" style="margin: 32px; max-width: 500px">
                <div class="title-bar">
                  <div class="title-bar-text">"bcrypt"</div>
                  <div class="title-bar-controls">
                  </div>
                </div>
                <fieldset style="">
                    <div class="field-row-stacked">
                        <label>"Password: "</label>
                        <input onkeyup={onkeyup_value} value={&data.current.value } />
                    </div>
                    <div class="field-row-stacked" style="width: 300px">
                        <label>"Salt: "</label>
                        
                        <input style={salt_style} onkeyup={onkeyup_salt} value={&data.current.salt} />
                    </div>
                    <div class="field-row-stacked">
                        <label>"Cost: " { data.current.cost }</label>
                        <input style="max-width: 80px;" onchange={onchange_cost} type="range" min="4" max="8" value="4" />
                    </div>
                    <div class="field-row-stacked">
                        "Bcrypt result: "
                        <pre>{ &data.last_result }</pre>
                    </div>
                </fieldset>
            </div>
        }
    })
}

fn main() {
    kobold::start(view! {
        <Bcryptor />
    });
}


fn hex<'sc>(scratch: &'sc mut [u8], data: &[u8]) -> Result<&'sc str, ()> {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    {
        let mut scratch_iter = scratch.iter_mut();
        for by in data {
            let hbyte = scratch_iter.next().ok_or(())?;
            *hbyte = HEX_CHARS[usize::from(*by) >> 4];
            let hbyte = scratch_iter.next().ok_or(())?;
            *hbyte = HEX_CHARS[usize::from(*by) & 0xF];
        }
    }

    Ok(str::from_utf8(&scratch[..data.len() * 2]).unwrap())
}

fn dehex_fixed_size<'a>(val: &str, into: &'a mut [u8]) -> Result<&'a [u8], ()> {
    fn nibble_from_char(ch: u8) -> Result<u8, ()> {
        match ch {
            b'A'..=b'F' => Ok(ch - b'A' + 10),
            b'a'..=b'f' => Ok(ch - b'a' + 10),
            b'0'..=b'9' => Ok(ch - b'0'),
            _ => Err(()),
        }
    }

    let mut copied_bytes = 0;
    let mut inbytes = val.bytes();
    for oby in into.iter_mut() {
        let mut buf = 0;
        if let Some(ch) = inbytes.next() {
            buf |= nibble_from_char(ch)?;
        } else {
            return Err(());
        }
        buf <<= 4;
        if let Some(ch) = inbytes.next() {
            buf |= nibble_from_char(ch)?;
        } else {
            return Err(());
        }
        *oby = buf;
        copied_bytes += 1;
    }
    Ok(&into[..copied_bytes])
}

