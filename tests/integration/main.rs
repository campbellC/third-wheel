use harness::MyRequest;
use simple_logger::SimpleLogger;

mod harness;

#[tokio::test]
async fn simple_get_request_passed_through_correctly() {
    SimpleLogger::new().init().unwrap();
    let test_harness = harness::set_up_for_trivial_mitm_test().await;
    let response_body = test_harness
        .client
        .get(format!("https:/{}/", test_harness.test_site_and_port))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let deserialized: MyRequest = serde_json::from_str(&response_body).unwrap();

    assert_eq!(deserialized.method, "GET");
    assert_eq!(deserialized.path, "/");
    assert_eq!(deserialized.query_params, "");
    assert_eq!(deserialized.body, "");

    // TODO: figure out what the headers *should* be
}
