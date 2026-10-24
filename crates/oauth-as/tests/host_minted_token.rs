// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Alex Fishlock

//! Host-minted access tokens ([`AccessTokenMinter`]): the host supplies the `access_token` string
//! and the crate persists the record under it, so RFC 7662 introspection, RFC 7009 revocation and
//! the refresh chain all operate on exactly the value the client holds.
//!
//! The failure each test guards against is a token that the client holds but this AS does not
//! recognise, or one this AS recognises but never handed out: the opaque string drawn for the
//! token id must never reach the store or the wire in place of the host's.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AccessTokenMinter, AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode,
    GrantType, MemoryStorage, MintError, MintRequest, ScopeSet, ServerConfig, TokenRequest,
    TokenResponse,
};

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// What the minter was asked, copied out of the borrowed [`MintRequest`].
#[derive(Debug, Clone)]
struct Seen {
    client_id: ClientId,
    subject: Option<String>,
    scope: ScopeSet,
    resource: Vec<String>,
    grant_type: GrantType,
    issued_at: SystemTime,
    expires_at: SystemTime,
    token_id: String,
}

#[derive(Clone, Copy)]
enum Mode {
    Mint,
    Fail,
    Denied,
    /// Mint the first token, deny every later one: a subject disabled between issuance and refresh.
    DenyAfterFirst,
    Empty,
    NotB64Token,
}

#[derive(Clone)]
struct RecordingMinter {
    mode: Mode,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl RecordingMinter {
    fn new(mode: Mode) -> Self {
        RecordingMinter {
            mode,
            seen: Arc::default(),
        }
    }
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl AccessTokenMinter for RecordingMinter {
    async fn mint(&self, request: MintRequest<'_>) -> Result<String, MintError> {
        let mut seen = self.seen.lock().unwrap();
        seen.push(Seen {
            client_id: request.client_id.clone(),
            subject: request.subject.map(str::to_owned),
            scope: request.scope.clone(),
            resource: request.resource.to_vec(),
            grant_type: request.grant_type,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            token_id: request.token_id.to_owned(),
        });
        match self.mode {
            Mode::Mint => Ok(format!("host-credential-{}", seen.len())),
            Mode::Fail => Err(MintError::new("credential service unavailable")),
            Mode::Denied => Err(MintError::denied("subject disabled")),
            Mode::DenyAfterFirst if seen.len() == 1 => Ok("host-credential-1".into()),
            Mode::DenyAfterFirst => Err(MintError::denied("subject disabled")),
            Mode::Empty => Ok(String::new()),
            Mode::NotB64Token => Ok("host credential".into()),
        }
    }
}

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Test device".into()),
        registration: None,
    }
}

async fn server_with(
    clock: ManualClock,
    minter: RecordingMinter,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock)
        .with_access_token_minter(minter);
    srv.register_client(device_client()).await.unwrap();
    srv
}

async fn device_grant(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    clock: &ManualClock,
) -> Result<TokenResponse, oauth_as::ErrorResponse> {
    let client_id = ClientId::new("device-client");
    let scope = ScopeSet::parse("read write").unwrap();
    let auth = srv
        .device_authorization(&client_id, None, Some(&scope))
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "user-42")
        .await
        .unwrap();
    clock.advance(Duration::from_secs(5));
    srv.token(TokenRequest::DeviceCode {
        client_id,
        client_secret: None,
        device_code: auth.device_code,
    })
    .await
}

#[tokio::test]
async fn device_grant_returns_the_host_string_and_introspection_finds_it() {
    let clock = ManualClock::at_epoch();
    let minter = RecordingMinter::new(Mode::Mint);
    let srv = server_with(clock.clone(), minter.clone()).await;

    let token = device_grant(&srv, &clock).await.unwrap();
    assert_eq!(token.access_token, "host-credential-1");
    assert_eq!(token.expires_in, 3600);

    let seen = minter.seen();
    assert_eq!(seen.len(), 1, "minted exactly once");
    let seen = &seen[0];
    assert_eq!(seen.client_id, ClientId::new("device-client"));
    assert_eq!(seen.subject.as_deref(), Some("user-42"));
    assert_eq!(seen.scope, ScopeSet::parse("read write").unwrap());
    assert!(seen.resource.is_empty());
    assert_eq!(seen.grant_type, GrantType::DeviceCode);
    assert_eq!(seen.issued_at, clock.now());
    assert_eq!(
        seen.expires_at,
        seen.issued_at + Duration::from_secs(token.expires_in),
        "the host is told the same expiry the client is"
    );
    assert!(seen.token_id.len() >= 43, "{}", seen.token_id);

    let info = srv
        .introspect(&token.access_token)
        .await
        .unwrap()
        .expect("the host string is the live token");
    assert_eq!(info.subject.as_deref(), Some("user-42"));
    assert_eq!(info.expires_at, seen.expires_at);
    assert!(
        srv.introspect(&seen.token_id).await.unwrap().is_none(),
        "the crate's own random id must not also be a live token"
    );
}

#[tokio::test]
async fn revocation_of_the_host_string_kills_it() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), RecordingMinter::new(Mode::Mint)).await;
    let token = device_grant(&srv, &clock).await.unwrap();

    srv.revoke(
        &ClientId::new("device-client"),
        None,
        &token.access_token,
        None,
    )
    .await
    .unwrap();
    assert!(srv.introspect(&token.access_token).await.unwrap().is_none());
}

#[tokio::test]
async fn refresh_rotation_mints_through_the_host_again() {
    let clock = ManualClock::at_epoch();
    let minter = RecordingMinter::new(Mode::Mint);
    let srv = server_with(clock.clone(), minter.clone()).await;
    let first = device_grant(&srv, &clock).await.unwrap();

    let second = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: first.refresh_token.expect("refresh issued by default"),
            scope: None,
        })
        .await
        .unwrap();
    assert_eq!(second.access_token, "host-credential-2");

    let seen = minter.seen();
    assert_eq!(seen[1].grant_type, GrantType::RefreshToken);
    assert_eq!(seen[1].subject.as_deref(), Some("user-42"));
    assert!(srv
        .introspect(&second.access_token)
        .await
        .unwrap()
        .is_some());
}

/// Fail closed: no fallback to the opaque string, and nothing persisted under either value.
async fn assert_refused_and_nothing_persisted(mode: Mode, expected: ErrorCode) {
    let clock = ManualClock::at_epoch();
    let minter = RecordingMinter::new(mode);
    let srv = server_with(clock.clone(), minter.clone()).await;

    let err = device_grant(&srv, &clock).await.unwrap_err();
    assert_eq!(err.error, expected);

    let seen = minter.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        srv.introspect(&seen[0].token_id).await.unwrap().is_none(),
        "a refused mint must not fall back to persisting the opaque id"
    );
    for candidate in ["", "host credential"] {
        assert!(srv.introspect(candidate).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn a_minter_error_is_server_error_and_persists_nothing() {
    assert_refused_and_nothing_persisted(Mode::Fail, ErrorCode::ServerError).await;
}

/// RFC 8628 s3.5: the host refusing the subject at poll time is the grant being denied, which the
/// device must be told so it stops polling, not a server fault it should retry.
#[tokio::test]
async fn a_denied_mint_on_the_device_grant_is_access_denied() {
    assert_refused_and_nothing_persisted(Mode::Denied, ErrorCode::AccessDenied).await;
    assert_eq!(ErrorCode::AccessDenied.http_status(), 400);
}

/// RFC 6749 s5.2 defines no `access_denied` at the token endpoint outside the device grant; a
/// refresh the host will no longer honour is a grant that is no longer valid, `invalid_grant`.
#[tokio::test]
async fn a_denied_mint_on_refresh_is_invalid_grant_and_persists_nothing() {
    let clock = ManualClock::at_epoch();
    let minter = RecordingMinter::new(Mode::DenyAfterFirst);
    let srv = server_with(clock.clone(), minter.clone()).await;
    let first = device_grant(&srv, &clock).await.unwrap();

    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: first.refresh_token.expect("refresh issued by default"),
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
    let seen = minter.seen();
    assert_eq!(seen.len(), 2);
    assert!(srv.introspect(&seen[1].token_id).await.unwrap().is_none());
}

#[tokio::test]
async fn an_empty_host_string_is_refused() {
    assert_refused_and_nothing_persisted(Mode::Empty, ErrorCode::ServerError).await;
}

#[tokio::test]
async fn a_host_string_outside_rfc6750_b64token_is_refused() {
    assert_refused_and_nothing_persisted(Mode::NotB64Token, ErrorCode::ServerError).await;
}

/// A host that configured RFC 9068 signing AND installed a minter has said two contradictory
/// things about what the wire token is. Neither is silently preferred.
#[cfg(feature = "jwt-p256")]
#[tokio::test]
async fn a_minter_together_with_jwt_format_is_refused() {
    use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};

    let clock = ManualClock::at_epoch();
    let minter = RecordingMinter::new(Mode::Mint);
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("kid"),
        "https://rs.example",
    )));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock.clone())
        .with_access_token_minter(minter.clone());
    srv.register_client(device_client()).await.unwrap();

    let err = device_grant(&srv, &clock).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::ServerError);
    assert!(minter.seen().is_empty(), "nothing minted");
}

/// The device code is spent by the refused redemption, exactly as by a successful one: the
/// approved grant is taken atomically before minting, so a refused mint is a terminal answer and
/// a second poll cannot reach the minter again (RFC 8628 s3.5: the device stops on any error
/// other than `authorization_pending` and `slow_down`).
#[tokio::test]
async fn a_refused_mint_spends_the_device_code() {
    for mode in [Mode::Fail, Mode::Denied, Mode::Empty] {
        let clock = ManualClock::at_epoch();
        let minter = RecordingMinter::new(mode);
        let srv = server_with(clock.clone(), minter.clone()).await;
        let client_id = ClientId::new("device-client");
        let auth = srv
            .device_authorization(&client_id, None, None)
            .await
            .unwrap();
        srv.approve_device(&auth.user_code, "user-42")
            .await
            .unwrap();
        let poll = || TokenRequest::DeviceCode {
            client_id: client_id.clone(),
            client_secret: None,
            device_code: auth.device_code.clone(),
        };

        clock.advance(Duration::from_secs(5));
        assert!(srv.token(poll()).await.is_err());
        clock.advance(Duration::from_secs(5));
        let again = srv.token(poll()).await.unwrap_err();
        assert_eq!(again.error, ErrorCode::InvalidGrant);
        assert_eq!(minter.seen().len(), 1, "minted at most once per approval");
    }
}
