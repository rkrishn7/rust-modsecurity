use modsecurity::{ModSecurity, Rules, Transaction};

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

    let mut transaction: Transaction =
        Transaction::new(&ms, &rules, Some(Box::new(|msg| println!("Log: {}", msg))));
    transaction
        .process_connection("127.0.0.1", 12345, "127.0.0.1", 8080)
        .expect("error processing connection");
    transaction
        .process_logging()
        .expect("error processing logging");
}
