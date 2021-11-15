use crate::harness::{set_up_for_trivial_mitm_test, MyRequest};

#[tokio::test]
#[ignore]
async fn simple_get() {
    let test_harness = set_up_for_trivial_mitm_test().await;

    let proxied_response = test_harness
        .client
        .get(format!("https://{}/echo", test_harness.test_site_and_port))
        .send()
        .await
        .unwrap();

    let non_proxied_response = test_harness
        .non_proxied_client
        .get(format!("https://{}/echo", test_harness.test_site_and_port))
        .send()
        .await
        .unwrap();

    compare_responses(proxied_response, non_proxied_response).await;
}

#[tokio::test]
#[ignore]
async fn query_params_get_request() {
    let test_harness = set_up_for_trivial_mitm_test().await;

    let proxied_response = test_harness
        .client
        .get(format!(
            "https://{}/echo/query?a=b&c=d",
            test_harness.test_site_and_port
        ))
        .send()
        .await
        .unwrap();

    let non_proxied_response = test_harness
        .non_proxied_client
        .get(format!(
            "https://{}/echo/query?a=b&c=d",
            test_harness.test_site_and_port
        ))
        .send()
        .await
        .unwrap();

    compare_responses(proxied_response, non_proxied_response).await;
}

#[tokio::test]
async fn ws_test() {
    let test_harness = set_up_for_trivial_mitm_test().await;
    let body = "this is a body";
    let proxied_response = test_harness
        .client
        .post(format!("https://{}/ws", test_harness.test_site_and_port))
        .body(body)
        .send()
        .await
        .unwrap();

    let non_proxied_response = test_harness
        .non_proxied_client
        .post(format!("https://{}/echo", test_harness.test_site_and_port))
        .body(body)
        .send()
        .await
        .unwrap();

    compare_responses(proxied_response, non_proxied_response).await;
}

#[tokio::test]
#[ignore]
async fn post_with_body() {
    let test_harness = set_up_for_trivial_mitm_test().await;
    let body = "this is a body";
    let proxied_response = test_harness
        .client
        .post(format!("https://{}/echo", test_harness.test_site_and_port))
        .body(body)
        .send()
        .await
        .unwrap();

    let non_proxied_response = test_harness
        .non_proxied_client
        .post(format!("https://{}/echo", test_harness.test_site_and_port))
        .body(body)
        .send()
        .await
        .unwrap();

    compare_responses(proxied_response, non_proxied_response).await;
}

async fn compare_responses(
    proxied_response: reqwest::Response,
    non_proxied_response: reqwest::Response,
) {
    assert_eq!(proxied_response.status(), non_proxied_response.status());
    assert_eq!(proxied_response.url(), non_proxied_response.url());
    assert_eq!(proxied_response.version(), non_proxied_response.version());
    assert_eq!(proxied_response.headers(), non_proxied_response.headers());

    let proxied_response_body = proxied_response.text().await.unwrap();
    let proxied_request: MyRequest = serde_json::from_str(&proxied_response_body).unwrap();

    let non_proxied_response_body = non_proxied_response.text().await.unwrap();
    let non_proxied_request: MyRequest = serde_json::from_str(&non_proxied_response_body).unwrap();

    assert_eq!(proxied_request, non_proxied_request);
}
