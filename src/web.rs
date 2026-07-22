use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tracing::{error, info};

use crate::{
    config::{Config, normalize_hex},
    impinj::ReaderHealth,
    store::{Store, TagOwner, TagRecord, now_ms},
    unifi::{UnifiClient, UnifiUser},
};

const OPERATOR_EMAIL_HEADER: &str = "cf-access-authenticated-user-email";

#[derive(Clone)]
struct AppState {
    db_path: Arc<PathBuf>,
    unifi: Option<UnifiClient>,
    claim_window: Duration,
    reader_health: ReaderHealth,
    health_stale_after: Duration,
    started_at: Instant,
}

pub struct WebHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl WebHandle {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    email: String,
    claim_window_ms: u64,
}

#[derive(Debug, Deserialize)]
struct UserQuery {
    #[serde(default)]
    q: String,
}

#[derive(Debug, Deserialize)]
struct TagQuery {
    #[serde(default = "default_tag_limit")]
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct ClaimRequest {
    user_id: String,
    #[serde(default)]
    vehicle_description: String,
}

#[derive(Debug, Serialize)]
struct ClaimResponse {
    tid: String,
    owner: TagOwner,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    reader: &'static str,
    reader_last_activity_ms_ago: Option<u64>,
    database: &'static str,
    uptime_seconds: u64,
    version: &'static str,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn upstream(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        error!(%error, "operator UI request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal service error".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

pub async fn start(
    config: &Config,
    unifi: Option<UnifiClient>,
    reader_health: ReaderHealth,
) -> Result<WebHandle> {
    let listener = TcpListener::bind(config.web_bind)
        .await
        .with_context(|| format!("failed to bind operator UI to {}", config.web_bind))?;
    let state = AppState {
        db_path: Arc::new(config.state_db.clone()),
        unifi,
        claim_window: config.claim_window,
        reader_health,
        health_stale_after: config.health_stale_after,
        started_at: Instant::now(),
    };
    let mut router = Router::new();
    if config.health_enabled {
        router = router.route("/healthz", get(health));
    }
    if config.web_enabled {
        router = router
            .route("/", get(index))
            .route("/app.css", get(stylesheet))
            .route("/app.js", get(javascript))
            .route("/api/session", get(session))
            .route("/api/tags", get(tags))
            .route("/api/users", get(users))
            .route("/api/tags/{tid}/claim", post(claim))
            .route("/api/tags/{tid}/revoke", post(revoke));
    }
    let router = router.with_state(state);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let address = config.web_bind;
    let task = tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = shutdown_receiver.await;
        });
        if let Err(error) = server.await {
            error!(%error, "operator UI stopped unexpectedly");
        }
    });
    info!(%address, "gateway HTTP service listening on loopback");
    Ok(WebHandle {
        shutdown: Some(shutdown_sender),
        task,
    })
}

async fn health(State(state): State<AppState>) -> Response {
    let snapshot = state.reader_health.snapshot();
    let age_ms = snapshot
        .last_activity_ms
        .map(|last| now_ms().saturating_sub(last).max(0) as u64);
    let reader_recent = age_ms.is_some_and(|age| age <= duration_ms(state.health_stale_after));
    let reader_status = if snapshot.connected {
        "connected"
    } else if reader_recent {
        "reconnecting"
    } else {
        "stale"
    };
    let database_ok =
        match Store::open(&state.db_path, "health").and_then(|store| store.health_check()) {
            Ok(()) => true,
            Err(error) => {
                error!(%error, "health check could not access RFID state database");
                false
            }
        };
    let healthy = reader_recent && database_ok;
    let body = HealthResponse {
        status: if healthy { "ok" } else { "unhealthy" },
        reader: reader_status,
        reader_last_activity_ms_ago: age_ms,
        database: if database_ok { "ok" } else { "error" },
        uptime_seconds: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    };
    let mut response = (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(body),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn index(headers: HeaderMap) -> Result<Response, ApiError> {
    operator_email(&headers)?;
    Ok(static_response("text/html; charset=utf-8", INDEX_HTML))
}

async fn stylesheet(headers: HeaderMap) -> Result<Response, ApiError> {
    operator_email(&headers)?;
    Ok(static_response("text/css; charset=utf-8", APP_CSS))
}

async fn javascript(headers: HeaderMap) -> Result<Response, ApiError> {
    operator_email(&headers)?;
    Ok(static_response(
        "application/javascript; charset=utf-8",
        APP_JS,
    ))
}

async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    Ok(Json(SessionResponse {
        email: operator_email(&headers)?,
        claim_window_ms: state
            .claim_window
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
    }))
}

async fn tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TagQuery>,
) -> Result<Json<Vec<TagRecord>>, ApiError> {
    operator_email(&headers)?;
    let store = Store::open(&state.db_path, "operator-ui").map_err(ApiError::internal)?;
    let tags = store
        .list_tags(query.limit.clamp(1, 500))
        .map_err(ApiError::internal)?;
    Ok(Json(tags))
}

async fn users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> Result<Json<Vec<UnifiUser>>, ApiError> {
    operator_email(&headers)?;
    if query.q.len() > 100 {
        return Err(ApiError::bad_request("user search is too long"));
    }
    unifi(&state)?
        .list_users(&query.q)
        .await
        .map(Json)
        .map_err(ApiError::upstream)
}

async fn claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tid): Path<String>,
    Json(request): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    let operator = operator_email(&headers)?;
    let tid = normalize_hex(&tid, None, "TID")
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let user = unifi(&state)?
        .validate_claim_user(request.user_id.trim())
        .await
        .map_err(ApiError::upstream)?;
    let mut store = Store::open(&state.db_path, operator).map_err(ApiError::internal)?;
    let vehicle = request.vehicle_description.trim();
    let owner = store
        .claim_tag(
            &tid,
            &user.id,
            &user.display_name(),
            (!vehicle.is_empty()).then_some(vehicle),
            state.claim_window,
        )
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(ClaimResponse { tid, owner }))
}

fn unifi(state: &AppState) -> Result<&UnifiClient, ApiError> {
    state.unifi.as_ref().ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!(
            "operator UI route was enabled without a UniFi client"
        ))
    })
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tid): Path<String>,
) -> Result<StatusCode, ApiError> {
    let operator = operator_email(&headers)?;
    let tid = normalize_hex(&tid, None, "TID")
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let mut store = Store::open(&state.db_path, operator).map_err(ApiError::internal)?;
    store
        .revoke_tag(&tid)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

fn operator_email(headers: &HeaderMap) -> Result<String, ApiError> {
    let email = headers
        .get(OPERATOR_EMAIL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::forbidden("Cloudflare Access identity is required"))?;
    Ok(email)
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response = Html(body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

const fn default_tag_limit() -> usize {
    200
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>FCR Gate Tag Registry</title>
  <link rel="stylesheet" href="/app.css">
  <script src="/app.js" defer></script>
</head>
<body>
  <header class="topbar">
    <div>
      <p class="eyebrow">Falls Creek Ranch</p>
      <h1>Gate tag registry</h1>
    </div>
    <div class="operator" id="operator">Checking access…</div>
  </header>
  <main>
    <section class="summary" aria-label="Tag summary">
      <div><span id="unassigned-count">–</span><small>Unassigned</small></div>
      <div><span id="active-count">–</span><small>Active</small></div>
      <div><span id="recent-count">–</span><small>Seen in 60s</small></div>
    </section>

    <section class="panel claim-panel">
      <div class="panel-heading">
        <div>
          <p class="eyebrow">Controlled enrollment</p>
          <h2>Assign a recently observed tag</h2>
        </div>
        <p class="hint">The tag must be encoded and visible to the reader within the claim window.</p>
      </div>
      <div class="claim-grid">
        <div>
          <label>Selected tag</label>
          <div class="selection empty" id="tag-selection">Select an unassigned tag below</div>
        </div>
        <div>
          <label for="user-search">UniFi Access user</label>
          <input id="user-search" type="search" placeholder="Search name, email, or employee number" autocomplete="off">
          <div class="user-results" id="user-results" role="listbox"></div>
          <div class="selection empty" id="user-selection">No user selected</div>
        </div>
        <div>
          <label for="vehicle">Vehicle description <span>optional</span></label>
          <input id="vehicle" maxlength="200" placeholder="White Ford pickup">
          <button class="primary" id="claim-button" disabled>Assign tag to user</button>
          <p class="message" id="message" role="status"></p>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-heading">
        <div>
          <p class="eyebrow">Live inventory</p>
          <h2>Encoded tags</h2>
        </div>
        <button class="secondary" id="refresh-button">Refresh</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Tag</th><th>Status</th><th>Last seen</th><th>Signal</th><th>Owner / vehicle</th><th></th></tr></thead>
          <tbody id="tag-rows"><tr><td colspan="6" class="loading">Loading tags…</td></tr></tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>"#;

const APP_CSS: &str = r#":root{color-scheme:dark;--bg:#0c1110;--panel:#131b18;--line:#29352f;--muted:#91a099;--text:#edf5f1;--accent:#73e2a7;--accent2:#1e6f4d;--danger:#ff8c82;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% -10%,#193d2e 0,transparent 38%),var(--bg);color:var(--text);min-height:100vh}.topbar{display:flex;justify-content:space-between;align-items:center;padding:28px clamp(20px,5vw,72px);border-bottom:1px solid var(--line);background:#0c1110cc;backdrop-filter:blur(12px);position:sticky;top:0;z-index:5}.eyebrow{margin:0 0 5px;color:var(--accent);font-size:.7rem;font-weight:750;letter-spacing:.16em;text-transform:uppercase}h1,h2{margin:0;letter-spacing:-.03em}h1{font-size:clamp(1.4rem,3vw,2.15rem)}h2{font-size:1.22rem}.operator{border:1px solid var(--line);border-radius:999px;padding:9px 14px;color:var(--muted);font-size:.82rem}main{width:min(1180px,calc(100% - 32px));margin:28px auto 70px}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px}.summary div{padding:18px 20px;border:1px solid var(--line);border-radius:14px;background:#101713}.summary span{display:block;font-size:1.85rem;font-weight:760}.summary small,.hint,label span{color:var(--muted)}.panel{border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,#151e1a,#101714);box-shadow:0 18px 60px #0004;margin-bottom:18px;overflow:hidden}.panel-heading{display:flex;justify-content:space-between;gap:24px;align-items:end;padding:22px 24px;border-bottom:1px solid var(--line)}.hint{max-width:460px;margin:0;font-size:.85rem;line-height:1.5}.claim-grid{display:grid;grid-template-columns:1fr 1.35fr 1fr;gap:18px;padding:24px}label{display:block;font-size:.76rem;font-weight:700;letter-spacing:.04em;margin-bottom:8px;text-transform:uppercase}input{width:100%;border:1px solid #35443d;background:#0b100e;color:var(--text);border-radius:10px;padding:12px;font:inherit;outline:none}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #73e2a71f}.selection{border:1px solid var(--accent2);border-radius:10px;padding:12px;background:#12261c;min-height:44px;font-size:.88rem}.selection.empty{border-color:var(--line);background:#0e1411;color:var(--muted)}.user-results{display:none;position:absolute;z-index:4;width:min(430px,calc(100vw - 64px));max-height:250px;overflow:auto;background:#0d1411;border:1px solid var(--line);border-radius:10px;margin-top:5px;box-shadow:0 16px 40px #0009}.user-results.open{display:block}.user-option{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid var(--line);border-radius:0;padding:11px 12px;background:transparent;color:var(--text)}.user-option:hover,.user-option:focus{background:#18251f}.user-option small{display:block;color:var(--muted);margin-top:3px}.primary,.secondary,.action{border:0;border-radius:10px;font:inherit;font-weight:720;cursor:pointer}.primary{width:100%;margin-top:16px;padding:12px;background:var(--accent);color:#07100b}.primary:disabled{opacity:.35;cursor:not-allowed}.secondary{padding:9px 13px;background:#1b2923;color:var(--text);border:1px solid var(--line)}.action{padding:7px 10px;background:#1b2923;color:var(--text)}.action.danger{color:var(--danger)}.message{min-height:20px;color:var(--accent);font-size:.83rem}.message.error{color:var(--danger)}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.86rem}th,td{padding:14px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;background:#101713}tbody tr:hover{background:#16201b}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}.status{display:inline-block;border-radius:999px;padding:5px 8px;background:#1b2923;color:var(--muted);font-size:.7rem;font-weight:750;text-transform:uppercase}.status.active{background:#174a32;color:#a9f0ca}.status.unassigned{background:#3a3020;color:#ffd994}.owner small{display:block;color:var(--muted);margin-top:3px}.loading{text-align:center;color:var(--muted);padding:32px}@media(max-width:800px){.topbar{position:static}.operator{display:none}.summary{grid-template-columns:1fr}.claim-grid{grid-template-columns:1fr}.panel-heading{align-items:start;flex-direction:column}.hint{max-width:none}th:nth-child(4),td:nth-child(4){display:none}}"#;

const APP_JS: &str = r#"const state={tags:[],selectedTag:null,selectedUser:null,claimWindowMs:60000};const $=id=>document.getElementById(id);async function api(path,options={}){const response=await fetch(path,{...options,headers:{'content-type':'application/json',...(options.headers||{})}});if(!response.ok){let message=`Request failed (${response.status})`;try{message=(await response.json()).error||message}catch{}throw new Error(message)}if(response.status===204)return null;return response.json()}function tagLabel(tag){return `RFID-${String(tag.sequence).padStart(8,'0')}`}function age(ms){if(!ms)return'Never';const seconds=Math.max(0,Math.round((Date.now()-ms)/1000));if(seconds<60)return`${seconds}s ago`;if(seconds<3600)return`${Math.floor(seconds/60)}m ago`;return`${Math.floor(seconds/3600)}h ago`}function setMessage(message,error=false){const el=$('message');el.textContent=message;el.classList.toggle('error',error)}function updateClaim(){const tag=$('tag-selection'),user=$('user-selection');if(state.selectedTag){tag.className='selection';tag.textContent=`${tagLabel(state.selectedTag)} · ${state.selectedTag.epc}`}else{tag.className='selection empty';tag.textContent='Select an unassigned tag below'}if(state.selectedUser){user.className='selection';user.textContent=`${state.selectedUser.full_name||`${state.selectedUser.first_name} ${state.selectedUser.last_name}`.trim()} · ${state.selectedUser.user_email||'No email'}`}else{user.className='selection empty';user.textContent='No user selected'}$('claim-button').disabled=!(state.selectedTag&&state.selectedUser)}function button(text,className,onClick){const b=document.createElement('button');b.type='button';b.className=className;b.textContent=text;b.addEventListener('click',onClick);return b}function renderTags(){const body=$('tag-rows');body.textContent='';const now=Date.now();let unassigned=0,active=0,recent=0;for(const tag of state.tags){if(tag.ownership_status==='unassigned'||tag.ownership_status==='revoked')unassigned++;if(tag.ownership_status==='active')active++;if(tag.last_seen_ms&&now-tag.last_seen_ms<state.claimWindowMs)recent++;const row=document.createElement('tr');const id=document.createElement('td');id.innerHTML=`<strong>${tagLabel(tag)}</strong><small class="mono"></small>`;id.querySelector('small').textContent=tag.epc;const status=document.createElement('td');const pill=document.createElement('span');pill.className=`status ${tag.ownership_status}`;pill.textContent=tag.ownership_status;status.append(pill);const seen=document.createElement('td');seen.textContent=age(tag.last_seen_ms);const rssi=document.createElement('td');rssi.textContent=tag.last_rssi_cdbm==null?'—':`${(tag.last_rssi_cdbm/100).toFixed(1)} dBm`;const owner=document.createElement('td');owner.className='owner';if(tag.owner){const name=document.createElement('strong');name.textContent=tag.owner.unifi_user_name;owner.append(name);if(tag.owner.vehicle_description){const v=document.createElement('small');v.textContent=tag.owner.vehicle_description;owner.append(v)}}else owner.textContent='—';const actions=document.createElement('td');if(tag.ownership_status==='active'){actions.append(button('Revoke','action danger',async()=>{if(!confirm(`Revoke ${tagLabel(tag)} from ${tag.owner.unifi_user_name}?`))return;try{await api(`/api/tags/${encodeURIComponent(tag.tid)}/revoke`,{method:'POST'});setMessage('Assignment revoked');await loadTags()}catch(error){setMessage(error.message,true)}}))}else{const eligible=tag.last_seen_ms&&now-tag.last_seen_ms<state.claimWindowMs;const select=button(eligible?'Select':'Present tag','action',()=>{if(!eligible)return;state.selectedTag=tag;updateClaim();window.scrollTo({top:0,behavior:'smooth'})});select.disabled=!eligible;actions.append(select)}row.append(id,status,seen,rssi,owner,actions);body.append(row)}$('unassigned-count').textContent=unassigned;$('active-count').textContent=active;$('recent-count').textContent=recent;if(!state.tags.length)body.innerHTML='<tr><td colspan="6" class="loading">No completed tags yet</td></tr>'}async function loadTags(){try{state.tags=await api('/api/tags?limit=300');if(state.selectedTag)state.selectedTag=state.tags.find(t=>t.tid===state.selectedTag.tid&&t.ownership_status!=='active')||null;renderTags();updateClaim()}catch(error){setMessage(error.message,true)}}let searchTimer;async function searchUsers(){const query=$('user-search').value.trim();const results=$('user-results');if(query.length<2){results.classList.remove('open');results.textContent='';return}try{const users=await api(`/api/users?q=${encodeURIComponent(query)}`);results.textContent='';for(const user of users.slice(0,30)){const name=user.full_name||`${user.first_name} ${user.last_name}`.trim();const option=button(name,'user-option',()=>{state.selectedUser=user;results.classList.remove('open');updateClaim()});const detail=document.createElement('small');detail.textContent=[user.user_email,user.employee_number&&`Employee ${user.employee_number}`].filter(Boolean).join(' · ');option.append(detail);results.append(option)}if(!users.length){const empty=document.createElement('div');empty.className='loading';empty.textContent='No active users found';results.append(empty)}results.classList.add('open')}catch(error){setMessage(error.message,true)}}$('user-search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(searchUsers,250)});$('claim-button').addEventListener('click',async()=>{if(!(state.selectedTag&&state.selectedUser))return;$('claim-button').disabled=true;setMessage('Validating UniFi access and assigning tag…');try{await api(`/api/tags/${encodeURIComponent(state.selectedTag.tid)}/claim`,{method:'POST',body:JSON.stringify({user_id:state.selectedUser.id,vehicle_description:$('vehicle').value})});setMessage(`Assigned ${tagLabel(state.selectedTag)} successfully`);state.selectedTag=null;state.selectedUser=null;$('vehicle').value='';$('user-search').value='';await loadTags();updateClaim()}catch(error){setMessage(error.message,true);updateClaim()}});$('refresh-button').addEventListener('click',loadTags);Promise.all([api('/api/session'),loadTags()]).then(([session])=>{state.claimWindowMs=session.claim_window_ms;$('operator').textContent=session.email;renderTags()}).catch(error=>setMessage(error.message,true));setInterval(loadTags,5000);"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GateMode, LprCorrelationMode};
    use tempfile::tempdir;

    fn state() -> AppState {
        AppState {
            db_path: Arc::new(PathBuf::from("unused")),
            unifi: Some(panic_client()),
            claim_window: Duration::from_secs(60),
            reader_health: ReaderHealth::default(),
            health_stale_after: Duration::from_secs(120),
            started_at: Instant::now(),
        }
    }

    fn panic_client() -> UnifiClient {
        let config = test_config();
        UnifiClient::new(&config).unwrap()
    }

    fn test_config() -> Config {
        Config {
            reader_base_url: "https://reader.test".into(),
            reader_username: "root".into(),
            reader_password: "secret".into(),
            verify_tls: false,
            ca_certificate: None,
            profile_id: "test".into(),
            antenna_port: 1,
            transmit_power_cdbm: 3000,
            rf_mode: 4,
            writes_enabled: false,
            default_epc: "300833B2DDD9014000000000".into(),
            epc_prefix: None,
            min_rssi_cdbm: -5000,
            confirm_reads: 5,
            confirm_window: Duration::from_secs(1),
            access_timeout: Duration::from_secs(15),
            retry_cooldown: Duration::from_secs(3),
            max_attempts: 3,
            state_db: PathBuf::from("unused"),
            tag_access_password: None,
            actor: "test".into(),
            web_enabled: true,
            health_enabled: true,
            health_stale_after: Duration::from_secs(120),
            web_bind: "127.0.0.1:8080".parse().unwrap(),
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9101".parse().unwrap(),
            claim_window: Duration::from_secs(60),
            lpr_correlation_mode: LprCorrelationMode::Disabled,
            lpr_correlation_window: Duration::from_secs(10),
            lpr_correlation_poll: Duration::from_secs(2),
            discovery_mode: LprCorrelationMode::Disabled,
            discovery_match_window: Duration::from_secs(10),
            discovery_poll: Duration::from_secs(2),
            discovery_passage_gap: Duration::from_secs(30),
            discovery_max_dwell: Duration::from_secs(120),
            discovery_min_rssi_cdbm: -6000,
            discovery_min_occurrences: 3,
            discovery_min_days: 2,
            discovery_min_confidence_percent: 80,
            discovery_conflict_occurrences: 2,
            discovery_evidence_retention: Duration::from_secs(60 * 86_400),
            discovery_lease: Duration::from_secs(60 * 86_400),
            gate_mode: GateMode::Disabled,
            gate_unlock_cooldown: Duration::from_secs(10),
            unifi_base_url: Some("https://unifi.test:12445".into()),
            unifi_api_key: Some("test-token".into()),
            unifi_verify_tls: false,
            unifi_ca_certificate: None,
            entry_gate_door_id: "1b620b81-f457-45f7-9fd2-27de1d8c4fdc".into(),
        }
    }

    #[test]
    fn cloudflare_operator_header_is_required() {
        let mut headers = HeaderMap::new();
        assert!(operator_email(&headers).is_err());
        headers.insert(
            OPERATOR_EMAIL_HEADER,
            HeaderValue::from_static("operator@example.com"),
        );
        assert_eq!(operator_email(&headers).unwrap(), "operator@example.com");
    }

    #[tokio::test]
    async fn every_operator_route_rejects_a_missing_cloudflare_identity() {
        let headers = HeaderMap::new();
        let app = state();
        let errors = [
            index(headers.clone()).await.unwrap_err(),
            stylesheet(headers.clone()).await.unwrap_err(),
            javascript(headers.clone()).await.unwrap_err(),
            session(State(app.clone()), headers.clone())
                .await
                .unwrap_err(),
            tags(
                State(app.clone()),
                headers.clone(),
                Query(TagQuery { limit: 10 }),
            )
            .await
            .unwrap_err(),
            users(
                State(app.clone()),
                headers.clone(),
                Query(UserQuery { q: "test".into() }),
            )
            .await
            .unwrap_err(),
            claim(
                State(app.clone()),
                headers.clone(),
                Path("E2801111".into()),
                Json(ClaimRequest {
                    user_id: "17d2f099-99df-429b-becb-1399a6937e5a".into(),
                    vehicle_description: String::new(),
                }),
            )
            .await
            .unwrap_err(),
            revoke(State(app), headers, Path("E2801111".into()))
                .await
                .unwrap_err(),
        ];
        assert!(
            errors
                .iter()
                .all(|error| error.status == StatusCode::FORBIDDEN)
        );
    }

    #[tokio::test]
    async fn static_ui_responses_have_security_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            OPERATOR_EMAIL_HEADER,
            HeaderValue::from_static("operator@example.com"),
        );
        let response = index(headers).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }

    #[tokio::test]
    async fn health_endpoint_accepts_recent_reader_activity_without_operator_identity() {
        let directory = tempdir().unwrap();
        let mut app = state();
        app.db_path = Arc::new(directory.path().join("state.sqlite3"));
        app.reader_health.mark_connected();

        let response = health(State(app.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

        app.reader_health.mark_disconnected();
        assert_eq!(health(State(app)).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_endpoint_fails_for_stale_reader_or_unusable_database() {
        let directory = tempdir().unwrap();
        let mut stale = state();
        stale.db_path = Arc::new(directory.path().join("state.sqlite3"));
        assert_eq!(
            health(State(stale)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let mut bad_database = state();
        bad_database.db_path = Arc::new(directory.path().to_path_buf());
        bad_database.reader_health.mark_connected();
        assert_eq!(
            health(State(bad_database)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
