//! Custom tower middleware layers for the JSON-RPC server.
//!
//! Both `RateLimitLayer` and `ApiKeyLayer` are `Clone` by design so they
//! can be composed with jsonrpsee's `set_http_middleware`.

use std::collections::HashMap;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use tower::{Layer, Service};

// ---------------------------------------------------------------------------
// RateLimitLayer — fixed-window request rate limiter keyed by auth context
// ---------------------------------------------------------------------------

/// Shared state for one fixed-window rate-limit bucket.
///
/// Buckets are keyed by coarse authentication context. The rate limiter must
/// never retain raw bearer tokens: authentication is handled separately by
/// [`ApiKeyLayer`], and untrusted token text is attacker-controlled input.
struct RateLimiterState {
    max_per_sec: u32,
    window_start: Instant,
    last_seen: Instant,
    count: u32,
}

impl RateLimiterState {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            window_start: Instant::now(),
            last_seen: Instant::now(),
            count: 0,
        }
    }

    /// Returns `true` if the request is allowed (within the current window).
    fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        self.last_seen = now;
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= self.max_per_sec {
            return false;
        }
        self.count += 1;
        true
    }
}

const MAX_RATE_LIMIT_BUCKETS: usize = 16;
const RATE_LIMIT_BUCKET_TTL: Duration = Duration::from_secs(60);

/// Tower layer that enforces a global request rate limit (req/sec).
/// Clone-compatible: all clones share the same `Arc<Mutex<RateLimiterState>>`.
#[derive(Clone)]
pub struct RateLimitLayer {
    buckets: Arc<Mutex<HashMap<String, RateLimiterState>>>,
    max_per_sec: u32,
}

impl RateLimitLayer {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_per_sec,
        }
    }

    /// Create from an optional config value. When `None`, the limit is set to
    /// `u32::MAX` (effectively disabled) so the layer type stays uniform.
    pub fn from_config(max_per_sec: Option<u32>) -> Self {
        Self::new(max_per_sec.unwrap_or(u32::MAX))
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            buckets: Arc::clone(&self.buckets),
            max_per_sec: self.max_per_sec,
        }
    }
}

/// Tower service produced by `RateLimitLayer`.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    buckets: Arc<Mutex<HashMap<String, RateLimiterState>>>,
    max_per_sec: u32,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RateLimitService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = futures_util::future::Either<
        S::Future,
        std::future::Ready<Result<Response<ResBody>, S::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let bucket_key = rate_limit_bucket_key(&req);
        let allowed = {
            let mut buckets = self.buckets.lock();
            prune_rate_limit_buckets(&mut buckets);
            buckets
                .entry(bucket_key)
                .or_insert_with(|| RateLimiterState::new(self.max_per_sec))
                .check_and_record()
        };

        if allowed {
            futures_util::future::Either::Left(self.inner.call(req))
        } else {
            let mut resp = Response::new(ResBody::default());
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            futures_util::future::Either::Right(std::future::ready(Ok(resp)))
        }
    }
}

fn rate_limit_bucket_key<B>(req: &Request<B>) -> String {
    if req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .is_some()
    {
        "authenticated".to_string()
    } else {
        "public".to_string()
    }
}

fn prune_rate_limit_buckets(buckets: &mut HashMap<String, RateLimiterState>) {
    if buckets.len() < MAX_RATE_LIMIT_BUCKETS {
        return;
    }
    let now = Instant::now();
    buckets.retain(|_, state| now.duration_since(state.last_seen) < RATE_LIMIT_BUCKET_TTL);
    if buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
        let mut keys_by_age: Vec<(String, Instant)> = buckets
            .iter()
            .map(|(key, state)| (key.clone(), state.last_seen))
            .collect();
        keys_by_age.sort_by_key(|(_, last_seen)| *last_seen);
        for (key, _) in keys_by_age
            .into_iter()
            .take(buckets.len().saturating_sub(MAX_RATE_LIMIT_BUCKETS - 1))
        {
            buckets.remove(&key);
        }
    }
}

// ---------------------------------------------------------------------------
// ApiKeyLayer — Bearer token authentication
// ---------------------------------------------------------------------------

/// Tower layer that enforces `Authorization: Bearer <key>` on **all** requests.
/// When `api_key` is `None`, the layer is a no-op pass-through.
/// Clone-compatible: holds the key in an `Arc<str>`.
///
/// Note: this layer authenticates every HTTP request regardless of the
/// JSON-RPC method name. All methods (reads and writes) require the Bearer
/// token when an API key is configured.
#[derive(Clone)]
pub struct ApiKeyLayer {
    api_key: Option<Arc<str>>,
}

impl ApiKeyLayer {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key: api_key.map(|k| Arc::from(k.as_str())),
        }
    }
}

impl<S> Layer<S> for ApiKeyLayer {
    type Service = ApiKeyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyService {
            inner,
            api_key: self.api_key.clone(),
        }
    }
}

/// Tower service produced by `ApiKeyLayer`.
#[derive(Clone)]
pub struct ApiKeyService<S> {
    inner: S,
    api_key: Option<Arc<str>>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ApiKeyService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = futures_util::future::Either<
        S::Future,
        std::future::Ready<Result<Response<ResBody>, S::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if let Some(ref key) = self.api_key {
            let expected = format!("Bearer {key}");
            let auth = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if auth != expected {
                let mut resp = Response::new(ResBody::default());
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                return futures_util::future::Either::Right(std::future::ready(Ok(resp)));
            }
        }
        futures_util::future::Either::Left(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response, StatusCode};
    use std::convert::Infallible;
    use tower::{Layer, Service, ServiceExt};

    // Minimal echo service for testing.
    #[derive(Clone)]
    struct OkService;
    impl Service<Request<()>> for OkService {
        type Response = Response<()>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request<()>) -> Self::Future {
            std::future::ready(Ok(Response::new(())))
        }
    }

    #[tokio::test]
    async fn rate_limit_allows_within_window() {
        let layer = RateLimitLayer::new(100);
        let mut svc = layer.layer(OkService);
        let req = Request::new(());
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_limit_rejects_over_quota() {
        let layer = RateLimitLayer::new(1);
        let mut svc = layer.layer(OkService);
        // First request: allowed.
        let _ = svc
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        // Second request in same second: rejected.
        let resp = svc
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn rate_limit_coalesces_bearer_token_buckets() {
        let layer = RateLimitLayer::new(1);
        let mut svc = layer.layer(OkService);
        let req_a1 = Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer a")
            .body(())
            .unwrap();
        let req_a2 = Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer a")
            .body(())
            .unwrap();
        let req_b = Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer b")
            .body(())
            .unwrap();

        let first = svc.ready().await.unwrap().call(req_a1).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second_same_token = svc.ready().await.unwrap().call(req_a2).await.unwrap();
        assert_eq!(second_same_token.status(), StatusCode::TOO_MANY_REQUESTS);
        let other_token = svc.ready().await.unwrap().call(req_b).await.unwrap();
        assert_eq!(other_token.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(layer.bucket_count(), 1);
    }

    #[tokio::test]
    async fn rate_limit_unique_bearer_headers_do_not_grow_bucket_map() {
        let layer = RateLimitLayer::new(10_000);
        let mut svc = layer.layer(OkService);

        for i in 0..128 {
            let req = Request::builder()
                .header(http::header::AUTHORIZATION, format!("Bearer token-{i}"))
                .body(())
                .unwrap();
            let resp = svc.ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        assert_eq!(layer.bucket_count(), 1);

        let public = svc
            .ready()
            .await
            .unwrap()
            .call(Request::new(()))
            .await
            .unwrap();
        assert_eq!(public.status(), StatusCode::OK);
        assert_eq!(layer.bucket_count(), 2);
    }

    #[tokio::test]
    async fn api_key_passes_with_correct_token() {
        let layer = ApiKeyLayer::new(Some("secret".into()));
        let mut svc = layer.layer(OkService);
        let req = Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer secret")
            .body(())
            .unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_key_rejects_wrong_token() {
        let layer = ApiKeyLayer::new(Some("secret".into()));
        let mut svc = layer.layer(OkService);
        let req = Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer wrong")
            .body(())
            .unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_key_disabled_passes_all() {
        let layer = ApiKeyLayer::new(None);
        let mut svc = layer.layer(OkService);
        let req = Request::new(());
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
