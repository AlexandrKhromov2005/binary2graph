use axum::{extract::State, response::Html, routing::get, Json, Router};
use std::sync::Arc;

pub struct AppState {
    pub report_json: String,
}

pub async fn serve(state: AppState, port: u16) {
    let shared = Arc::new(state);

    let app = Router::new()
        .route("/", get(index))
        .route("/api/report", get(report))
        .with_state(shared);

    let addr = format!("127.0.0.1:{}", port);
    println!("Serving on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("can't bind address");
    axum::serve(listener, app).await.expect("server failed");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn report(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(&state.report_json).expect("stored JSON is valid");
    Json(value)
}