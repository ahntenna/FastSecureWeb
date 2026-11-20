//! 진입점.
//!   server               API 서버 실행
//!   server healthcheck   컨테이너 HEALTHCHECK 용: 자기 자신의 /api/health 를 호출해 종료 코드로 알린다

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use server::config::Config;
use server::{build_app, build_state};

/// 앱이 Host 검사를 하므로 ALLOWED_HOSTS 의 첫 번째 값을 Host 헤더로 쓴다.
fn healthcheck(cfg: &Config) -> bool {
    let host = cfg.allowed_hosts.first().map(String::as_str).unwrap_or("localhost");
    let address = SocketAddr::from(([127, 0, 0, 1], cfg.port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(2)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET /api/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut reply = [0u8; 16];
    matches!(stream.read(&mut reply), Ok(n) if reply[..n].starts_with(b"HTTP/1.1 200"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(message) => {
            eprintln!("설정 오류: {message}");
            std::process::exit(2);
        }
    };

    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(if healthcheck(&cfg) { 0 } else { 1 });
    }

    // 컨테이너 로그에 색상 제어 문자가 섞이지 않게 한다.
    tracing_subscriber::fmt().with_target(false).with_ansi(false).init();

    // 개발: 루프백에만 바인딩. 컨테이너: 같은 네트워크의 web(nginx)이 접근할 수 있게 전체 인터페이스.
    let host = if cfg.is_dev { [127, 0, 0, 1] } else { [0, 0, 0, 0] };
    let address = SocketAddr::from((host, cfg.port));

    let state = match build_state(cfg).await {
        Ok(state) => state,
        Err(message) => {
            eprintln!("기동 실패: {message}");
            std::process::exit(2);
        }
    };
    let app = build_app(state);

    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("포트를 열 수 없습니다 ({address}): {error}");
            std::process::exit(2);
        }
    };
    tracing::info!(%address, "listening");
    if let Err(error) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("서버 오류: {error}");
        std::process::exit(1);
    }
}
