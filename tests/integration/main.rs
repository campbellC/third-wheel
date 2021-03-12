use simple_logger::SimpleLogger;

mod harness;

#[tokio::test]
async fn foo() {
    SimpleLogger::new().init().unwrap();
    let test_harness = harness::set_up_for_test().await;
    println!("Here");
    let response_body = test_harness
        .client
        .get(format!("https:/{}/", test_harness.test_site_and_port))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("and Here");

    assert_eq!(response_body, "Hello, World!");
}
