//! MD5 Digest authentication (RFC 2617 §3.2.2).

use siphon_rtp_stun::turn::md5;

fn hexadecimal(input: &str) -> String {
    md5(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// RFC 2617 MD5 response, or RFC 2069 when the challenge has no qop.
pub fn response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    auth: Option<(&str, &str)>,
) -> String {
    let first = hexadecimal(&format!("{username}:{realm}:{password}"));
    let second = hexadecimal(&format!("{method}:{uri}"));
    match auth {
        Some((count, cnonce)) => {
            hexadecimal(&format!("{first}:{nonce}:{count}:{cnonce}:auth:{second}"))
        }
        None => hexadecimal(&format!("{first}:{nonce}:{second}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc2617_known_answer_with_auth() {
        assert_eq!(
            response(
                "Mufasa",
                "testrealm@host.com",
                "Circle Of Life",
                "GET",
                "/dir/index.html",
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                Some(("00000001", "0a4f113b"))
            ),
            "6629fae49393a05397450978507c4ef1"
        );
    }
    #[test]
    fn rfc2069_without_qop() {
        // H(939e7578ed9e3c518a452acee763bce9:nonce:39aff3a2bab6126f332b942af96d3366).
        assert_eq!(
            response(
                "Mufasa",
                "testrealm@host.com",
                "Circle Of Life",
                "GET",
                "/dir/index.html",
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                None
            ),
            "670fd8c2df070c60b045671b8b24ff02"
        );
    }
}
