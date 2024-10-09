use reqwest::blocking::Client;
use ring::hmac;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

const CSS: &str = r#"<style type="text/css">
.engine {
  font-family: "MiSansVF";
  font-size: 18px;
  color: #578bc5;
}
.originalText {
    font-size: 120%;
    font-family: "MiSansVF";
    font-weight: 600;
    display: inline-block;
    margin: 0rem 0rem 0rem 0rem;
    color: #2a5598;
    margin-bottom: 0.6rem;
}
.frame {
    margin: 1rem 0.5rem 0.5rem 0;
    padding: 0.7rem 0.5rem 0.5rem 0;
    border-top: 3px dashed #eaeef6;
}
definition {
    font-family: "MiSansVF";
    color: #2a5598;
    height: 120px;
    padding: 0.05em;
    font-weight: 500;
    font-size: 16px;
}
</style>"#;

fn sign(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&s_key, msg).as_ref().to_vec()
}

fn count_languages(text: &str) -> (usize, usize) {
    let mut chinese_count = 0;
    let mut english_count = 0;

    for ch in text.chars() {
        if ch.is_ascii() {
            english_count += 1; // 英文字符
        } else if is_chinese(ch) {
            chinese_count += 1; // 中文字符
        }
    }

    (chinese_count, english_count)
}

fn is_chinese(ch: char) -> bool {
    // 判断字符是否在中文范围内
    match ch {
        '\u{4E00}'..='\u{9FFF}' | // 常用汉字
        '\u{3400}'..='\u{4DBF}' | // 扩展A区
        '\u{20000}'..='\u{2A6DF}' | // 扩展B区
        '\u{2A700}'..='\u{2B73F}' | // 扩展C区
        '\u{2B740}'..='\u{2B81F}' | // 扩展D区
        '\u{2B820}'..='\u{2CEAF}' | // 扩展E区
        '\u{F900}'..='\u{FAFF}' | // 兼容汉字
        '\u{2F800}'..='\u{2FA1F}' => true, // 兼容汉字扩展
        _ => false,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Invalid arguments! Usage: {} <text>", args[0]);
        return Err("Invalid arguments".into());
    }
    let secret_id = match env::var("TENCENT_TRANSLATION_SECRET_ID") {
        Ok(val) => val,
        Err(_) => {
            println!("Please set TENCENT_TRANSLATION_SECRET_ID environment variable");
            return Err("Missing TENCENT_TRANSLATION_SECRET_ID".into());
        }
    };
    let secret_key = match env::var("TENCENT_TRANSLATION_SECRET_KEY") {
        Ok(val) => val,
        Err(_) => {
            println!("Please set TENCENT_TRANSLATION_SECRET_KEY environment variable");
            return Err("Missing TENCENT_TRANSLATION_SECRET_KEY".into());
        }
    };

    let (chinese_count, english_count) = count_languages(&args[1]);
    let language_to = if chinese_count > english_count {
        "en"
    } else {
        "zh"
    };

    let service = "tmt";
    let host = "tmt.tencentcloudapi.com";
    let region = "ap-guangzhou";
    let version = "2018-03-21";
    let action = "TextTranslate";
    let payload = json!({
        "SourceText": args[1],
        "Source": "auto",
        "Target": language_to,
        "ProjectId": 0
    });
    let endpoint = "https://tmt.tencentcloudapi.com";
    let algorithm = "TC3-HMAC-SHA256";

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let date = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();

    // Step 1: Create Canonical Request
    let http_request_method = "POST";
    let canonical_uri = "/";
    let canonical_querystring = "";
    let ct = "application/json; charset=utf-8";
    let canonical_headers = format!(
        "content-type:{}\nhost:{}\nx-tc-action:{}\n",
        ct,
        host,
        action.to_lowercase()
    );
    let signed_headers = "content-type;host;x-tc-action";
    let hashed_request_payload =
        ring::digest::digest(&ring::digest::SHA256, payload.to_string().as_bytes());
    let payload_hash = hex::encode(hashed_request_payload);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        http_request_method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    );

    // Step 2: Create String to Sign
    let credential_scope = format!("{}/{}/tc3_request", date, service);
    let hashed_canonical_request =
        ring::digest::digest(&ring::digest::SHA256, canonical_request.as_bytes());
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        algorithm,
        timestamp,
        credential_scope,
        hex::encode(hashed_canonical_request)
    );

    // Step 3: Calculate Signature
    let secret_date = sign(format!("TC3{}", secret_key).as_bytes(), date.as_bytes());
    let secret_service = sign(&secret_date, service.as_bytes());
    let secret_signing = sign(&secret_service, b"tc3_request");
    let signature = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &secret_signing),
        string_to_sign.as_bytes(),
    );

    // Step 4: Create Authorization
    let authorization = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        algorithm,
        secret_id,
        credential_scope,
        signed_headers,
        hex::encode(signature)
    );

    // Step 5: Send Request
    let client = Client::new();
    let mut headers = HashMap::new();
    headers.insert("Authorization", authorization);
    headers.insert("Content-Type", ct.to_string());
    headers.insert("Host", host.to_string());
    headers.insert("X-TC-Action", action.to_string());
    headers.insert("X-TC-Timestamp", timestamp.to_string());
    headers.insert("X-TC-Version", version.to_string());
    // if !region.is_empty() {
    headers.insert("X-TC-Region", region.to_string());
    // }
    // if !token.is_empty() {
    //     headers.insert("X-TC-Token", token.to_string());
    // }
    // println!("{:?}", headers);
    let response = client
        .post(endpoint)
        .headers(reqwest::header::HeaderMap::from_iter(
            headers
                .iter()
                .map(|(k, v)| (k.parse().unwrap(), v.parse().unwrap())),
        ))
        .json(&payload)
        .send()?;

    let res = response.json::<serde_json::Value>()?;
    if let Some(text) = res["Response"]["TargetText"].as_str() {
        println!("{}", CSS);
        println!("<div class=\"originalText\">{}</div>", args[1]);
        println!("<br><br>");
        println!("<div class=\"frame\">");
        println!("<definition>{}</definition>", text);
        println!("</div>");
        println!("<br>");
        // println!("{}", text)
    } else {
        println!("Api response error! Response: {:?}", res);
    }
    Ok(())
}
