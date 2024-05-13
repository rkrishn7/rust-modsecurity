use modsecurity::{ModSecurity, Rules};

pub fn main() {
    let ms = ModSecurity::default();

    let mut rules = Rules::new();
    rules
        .add_plain(
            r#"
            SecRuleEngine On

            SecRule REQUEST_URI "@rx admin" "id:1,phase:1,deny,status:401"
        "#,
        )
        .expect("Failed to add rules");

    let mut transaction = ms
        .transaction_builder()
        .with_rules(&rules)
        .build()
        .expect("Error building transaction");

    transaction
        .process_uri("http://example.com/admin", "GET", "1.1")
        .expect("Error processing URI");
    transaction
        .process_request_headers()
        .expect("Error processing request headers");

    let intervention = transaction.intervention().expect("Expected intervention");

    assert_eq!(intervention.status(), 401);
}
