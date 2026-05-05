package transport

// This file is intentionally tiny — proxy resolution lives in
// transport.go alongside the rest of the http.Transport setup so
// there is exactly one place to read when reviewing the wire setup.
//
// The package currently exposes no proxy-only public API; the field
// on Options (`Proxy`) and the env-var fall-back via
// `http.ProxyFromEnvironment` together cover every per-request
// outcome we need. Per-registry proxies (spec section 9.4) land in
// Stage 10 alongside per-registry config.
