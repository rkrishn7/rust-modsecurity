use modsecurity::{ModSecurity, Rules};

pub fn main() {
    let ms = ModSecurity::default();

    let mut rules = Rules::new();
    rules
        .add_plain(
            r#"
            SecRuleEngine On

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
        .build()
        .expect("Error building transaction");

    transaction
        .add_request_header("X-Client-Port", "22")
        .expect("Error adding request header");
    transaction
        .process_request_headers()
        .expect("Error processing request headers");

    let intervention = transaction.intervention().expect("Expected intervention");

    assert_eq!(intervention.status(), 403);

    println!(
        "Received log: {}",
        intervention.log().expect("Expected log")
    );
}
