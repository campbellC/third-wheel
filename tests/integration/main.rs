use harness::MyRequest;

mod harness;

#[tokio::test]
async fn simple_get_request() {
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

#[tokio::test]
async fn query_params_get_request() {
    let test_harness = harness::set_up_for_trivial_mitm_test().await;
    let response_body = test_harness
        .client
        .get(format!("https:/{}/query?a=b&c=d", test_harness.test_site_and_port))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let deserialized: MyRequest = serde_json::from_str(&response_body).unwrap();

    assert_eq!(deserialized.method, "GET");
    assert_eq!(deserialized.path, "/query");
    assert_eq!(deserialized.query_params, "a=b&c=d");
    assert_eq!(deserialized.body, "");
}


#[tokio::test]
async fn post_body_correctly_sent() {
    let test_harness = harness::set_up_for_trivial_mitm_test().await;
    let body = "this is a body";
    let response_body = test_harness
        .client
        .post(format!("https:/{}/", test_harness.test_site_and_port))
        .body(body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let deserialized: MyRequest = serde_json::from_str(&response_body).unwrap();

    assert_eq!(deserialized.method, "POST");
    assert_eq!(deserialized.path, "/");
    assert_eq!(deserialized.query_params, "");
    assert_eq!(deserialized.body, body);
}
