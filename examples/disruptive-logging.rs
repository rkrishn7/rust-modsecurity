use modsecurity::{ModSecurity, Rules};

pub fn main() {
    let ms = ModSecurity::builder().with_log_callbacks().build();

    let mut rules = Rules::new();
    rules
        .add_plain(
            r#"
            SecRuleEngine DetectionOnly

            SecRule REQUEST_HEADERS:X-Client-Port "@streq 22" \
                    "id:'1234567',\
                    log,\
                    msg:'Blocking SSH port',\
                    phase:1,\
                    t:none,\
                    status:403,\
                    deny
        "#,
        )
        .expect("Failed to add rules");

    let mut transaction = ms
        .transaction_builder()
        .with_rules(&rules)
        .with_logging(|msg| {
            if let Some(msg) = msg {
                println!("Received log: {}", msg);
            }
        })
        .build()
        .expect("Error building transaction");

    transaction
        .add_request_header("X-Client-Port", "22")
        .expect("Error adding request header");
    transaction
        .process_request_headers()
        .expect("Error processing request headers");

    assert!(transaction.intervention().is_none());
}
