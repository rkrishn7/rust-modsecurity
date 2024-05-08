use modsecurity::{ModSecurity, Rules};

pub fn main() {
    let mut ms = ModSecurity::new();
    ms.enable_log_callbacks();
    println!("ModSecurity version: {}", ms.whoami());

    let mut rules = Rules::new();
    if let Err(e) = rules.add_file("examples/basic_rules.conf") {
        println!("Error adding rules file: {:?}", e);
        return;
    }

    rules.dump();

    println!("Rules added successfully");

    let mut transaction = ms
        .transaction_builder(&rules)
        .with_logging(|msg| println!("Log: {:?}", msg))
        .build()
        .expect("error building transaction");

    transaction
        .process_connection("127.0.0.2", 22, "127.0.0.3", 8080)
        .expect("error processing connection");
    transaction
        .process_request_body()
        .expect("error processing request body");
    transaction
        .add_request_header("X-Client-Port", "22")
        .expect("error adding request header");
    transaction
        .process_request_headers()
        .expect("error processing request headers");
    println!("intervention? {:?}", transaction.intervention());
    transaction
        .process_logging()
        .expect("error processing logging");
}
