//! Redirect construction for downstream OAuth authorization codes.

pub(crate) fn build_authorize_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut url = format!("{redirect_uri}{separator}code={}", percent_encode(code));
    if let Some(state) = state {
        url.push_str(&format!("&state={}", percent_encode(state)));
    }
    url
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
