//! Per-call timing with the actual HTTP response (or WebSocket upgrade) status.

use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use http::{Request, Response};
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::server::MethodResponse;
use parking_lot::Mutex;
use tower::{Layer, Service};

type Observer = dyn Fn(&str, u16, Duration) + Send + Sync;

/// Receives bounded method labels, transport status and elapsed handler time.
#[derive(Clone)]
pub struct RpcMetricsObserver(Arc<Observer>);

impl std::fmt::Debug for RpcMetricsObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpcMetricsObserver")
    }
}

impl RpcMetricsObserver {
    pub fn new(observer: impl Fn(&str, u16, Duration) + Send + Sync + 'static) -> Self {
        Self(Arc::new(observer))
    }
}

#[derive(Default)]
struct Observations {
    status: Option<u16>,
    pending: Vec<(String, Duration)>,
}

#[derive(Clone)]
struct RequestMetrics {
    observer: RpcMetricsObserver,
    state: Arc<Mutex<Observations>>,
}

impl RequestMetrics {
    fn record(&self, method: String, elapsed: Duration) {
        let status = {
            let mut state = self.state.lock();
            match state.status {
                Some(status) => status,
                None => {
                    state.pending.push((method, elapsed));
                    return;
                }
            }
        };
        (self.observer.0)(&method, status, elapsed);
    }

    fn finish(&self, status: u16, post: bool, elapsed: Duration) {
        let pending = {
            let mut state = self.state.lock();
            state.status = Some(status);
            std::mem::take(&mut state.pending)
        };
        if pending.is_empty() && post {
            // Authentication, HTTP rate limits and malformed input may stop
            // before JSON-RPC dispatch. Never label these with untrusted text.
            (self.observer.0)("__transport__", status, elapsed);
        }
        for (method, duration) in pending {
            (self.observer.0)(&method, status, duration);
        }
    }
}

#[derive(Clone)]
pub(crate) struct HttpMetricsLayer(pub Option<RpcMetricsObserver>);

impl<S> Layer<S> for HttpMetricsLayer {
    type Service = HttpMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService {
            inner,
            observer: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct HttpMetricsService<S> {
    inner: S,
    observer: Option<RpcMetricsObserver>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let metrics = self.observer.clone().map(|observer| RequestMetrics {
            observer,
            state: Arc::default(),
        });
        if let Some(metrics) = &metrics {
            req.extensions_mut().insert(metrics.clone());
        }
        let post = req.method() == http::Method::POST;
        let start = Instant::now();
        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await?;
            if let Some(metrics) = metrics {
                metrics.finish(response.status().as_u16(), post, start.elapsed());
            }
            Ok(response)
        })
    }
}

#[derive(Clone)]
pub(crate) struct RpcMetricsLayer(pub Arc<HashSet<String>>);

impl<S> Layer<S> for RpcMetricsLayer {
    type Service = RpcMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcMetricsService {
            inner,
            methods: Arc::clone(&self.0),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RpcMetricsService<S> {
    inner: S,
    methods: Arc<HashSet<String>>,
}

impl<'a, S> RpcServiceT<'a> for RpcMetricsService<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
    S::Future: Send + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: jsonrpsee::types::Request<'a>) -> Self::Future {
        let metrics = req.extensions().get::<RequestMetrics>().cloned();
        if metrics.is_none() {
            return Box::pin(self.inner.call(req));
        }
        let method = self
            .methods
            .get(req.method_name())
            .cloned()
            .unwrap_or_else(|| "__unknown__".into());
        let start = Instant::now();
        let future = self.inner.call(req);
        Box::pin(async move {
            let response = future.await;
            if let Some(metrics) = metrics {
                metrics.record(method, start.elapsed());
            }
            response
        })
    }
}
