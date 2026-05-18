const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const gatewayEl = document.getElementById('gateway');
const portEl = document.getElementById('port');
const usernameEl = document.getElementById('username');
const passwordEl = document.getElementById('password');
const saveCredsCheck = document.getElementById('saveCreds');
const brandSubtitleEl = document.getElementById('brandSubtitle');
const logoEl = document.getElementById('logo');
const logsBtn = document.getElementById('logsBtn');
const vpnForm = document.getElementById('vpnForm');
const statusLineEl = document.getElementById('statusLine');
const mainBtn = document.getElementById('mainBtn');
const togglePasswordBtn = document.getElementById('togglePassword');
const vpnCloseModal = document.getElementById('vpnCloseModal');
const vpnCloseModalTitle = document.getElementById('vpnCloseModalTitle');
const vpnCloseModalIntro = document.getElementById('vpnCloseModalIntro');
const vpnCloseModalStep1El = document.getElementById('vpnCloseModalStep1');
const vpnCloseModalStep2El = document.getElementById('vpnCloseModalStep2');
const vpnCloseModalForceWarning = document.getElementById('vpnCloseModalForceWarning');
const vpnCloseBtnDisconnectQuit = document.getElementById('vpnCloseBtnDisconnectQuit');
const vpnCloseBtnMoreOptions = document.getElementById('vpnCloseBtnMoreOptions');
const vpnCloseBtnForceQuit = document.getElementById('vpnCloseBtnForceQuit');
const vpnCloseBtnBack = document.getElementById('vpnCloseBtnBack');
const vpnCloseBtnStay = document.getElementById('vpnCloseBtnStay');
let isConnected = false;
let statusText = '';

/** Label pulsante modale «disconnetti e chiudi»; ripristino dopo errore/uscita dal flusso. */
const VPN_CLOSE_DISCONNECT_QUIT_LABEL = 'Disconnetti e chiudi';

let vpnCloseModalQuitFlowActive = false;

function formatInvokeError(err) {
  if (err == null) return 'Errore sconosciuto.';
  if (typeof err === 'string') return err;
  const m = err.message ?? err.error;
  if (typeof m === 'string' && m.trim()) return m.trim();
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }

}

/** Messaggio sotto il pulsante (accessibile con aria-live). */

function setInlineStatus(text, kind) {
  statusLineEl.textContent = text || '';
  statusLineEl.className = 'status-line' + (kind ? ` ${kind}` : '');

}

function clearInlineStatus() {
  setInlineStatus('', '');

}

/** Scrive su console e nella finestra Log dell’app (se il backend risponde). */

async function logToPanel(message) {
  console.warn('[PoliVPN]', message);
  try {
    await invoke('append_client_log', { message });
  } catch (e) {
    console.error('[PoliVPN] append_client_log:', e);
  }

}

/** Legge la porta dal campo UI (1–65535); se vuota o non valida usa 443. */

function parsePortFromUi() {
  const raw = portEl.value.trim();
  if (raw === '') return 443;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) return 443;
  return n;

}

/** Host solo: toglie http(s):// ripetuti e il path (evita https://https://…). */

function normalizeGatewayHost(raw) {
  let s = raw.trim();
  for (;;) {
    const lower = s.toLowerCase();
    if (lower.startsWith('https://')) {
      s = s.slice(8).trimStart();
    } else if (lower.startsWith('http://')) {
      s = s.slice(7).trimStart();
    } else {
      break;
    }
  }
  const slash = s.indexOf('/');
  if (slash !== -1) {
    s = s.slice(0, slash);
  }
  return s.trim().replace(/\/+$/, '');

}

function setConnecting(connecting) {
  mainBtn.className = 'btn btn-primary';
  if (connecting) {
    mainBtn.disabled = true;
    mainBtn.textContent = statusText || 'Connessione...';
  } else if (isConnected) {
    mainBtn.disabled = false;
    mainBtn.textContent = 'Disconnetti';
  } else {
    mainBtn.disabled = false;
    mainBtn.textContent = 'Connetti';
  }

}

function updateVpnConnectionStateLabel(status) {
  const valueEl = document.getElementById('vpnConnectionStateValue');
  if (!valueEl) return;
  const base = 'vpn-connection-state__value';
  valueEl.className = base;
  switch (status) {
    case 'Connected':
      valueEl.textContent = 'CONNESSA';
      valueEl.classList.add(`${base}--connected`);
      break;
    case 'Disconnected':
    case 'Error':
      valueEl.textContent = 'DISCONNESSA';
      valueEl.classList.add(`${base}--disconnected`);
      break;
    case 'Authenticating':
    case 'Connecting':
    case 'Disconnecting':
      valueEl.textContent = 'In corso…';
      valueEl.classList.add(`${base}--pending`);
      break;
    default:
      valueEl.textContent = 'DISCONNESSA';
      valueEl.classList.add(`${base}--disconnected`);
      break;
  }

}

function syncPasswordToggleAvailability() {
  if (!togglePasswordBtn) return;
  const showIcon = togglePasswordBtn.querySelector('.btn-toggle-password__icon--show');
  const hideIcon = togglePasswordBtn.querySelector('.btn-toggle-password__icon--hide');
  if (passwordEl.disabled && passwordEl.type === 'text') {
    passwordEl.type = 'password';
    if (showIcon && hideIcon) {
      showIcon.hidden = false;
      hideIcon.hidden = true;
    }
    togglePasswordBtn.setAttribute('aria-pressed', 'false');
    togglePasswordBtn.title = 'Mostra password';
    togglePasswordBtn.setAttribute('aria-label', 'Mostra password');
  }
  togglePasswordBtn.disabled = passwordEl.disabled;

}

async function registerStatusListener() {
  await listen('vpn-status-changed', (event) => {
    applyStatusTag(event.payload);
  });

}

/** Allinea UI allo stato VPN (stesso schema degli eventi). */

function applyStatusTag(status) {
  switch (status) {
    case 'Disconnected':
      isConnected = false;
      statusText = '';
      gatewayEl.disabled = false;
      portEl.disabled = false;
      usernameEl.disabled = false;
      passwordEl.disabled = false;
      setConnecting(false);
      break;
    case 'Authenticating':
      clearInlineStatus();
      statusText = 'Autenticazione...';
      gatewayEl.disabled = true;
      portEl.disabled = true;
      usernameEl.disabled = true;
      passwordEl.disabled = true;
      setConnecting(true);
      break;
    case 'Connecting':
      clearInlineStatus();
      statusText = 'Connessione...';
      setConnecting(true);
      break;
    case 'Connected':
      clearInlineStatus();
      isConnected = true;
      statusText = '';
      gatewayEl.disabled = true;
      portEl.disabled = true;
      usernameEl.disabled = true;
      passwordEl.disabled = true;
      setConnecting(false);
      break;
    case 'Disconnecting':
      clearInlineStatus();
      statusText = 'Disconnessione...';
      gatewayEl.disabled = true;
      portEl.disabled = true;
      usernameEl.disabled = true;
      passwordEl.disabled = true;
      setConnecting(true);
      break;
    case 'Error':
      isConnected = false;
      statusText = '';
      gatewayEl.disabled = false;
      portEl.disabled = false;
      usernameEl.disabled = false;
      passwordEl.disabled = false;
      setConnecting(false);
      break;
  }
  updateVpnConnectionStateLabel(status);
  syncPasswordToggleAvailability();
}

async function syncStatusFromBackend() {
  try {
    const tag = await invoke('get_status_plain');
    applyStatusTag(tag);
  } catch (_) {
    /* vecchia build */
  }

}

async function handleVpnFormSubmit(event) {
  event.preventDefault();
  if (isConnected) {
    clearInlineStatus();
    statusText = 'Disconnessione in corso...';
    setConnecting(true);
    try {
      await invoke('disconnect');
    } catch (err) {
      const msg = formatInvokeError(err);
      statusText = '';
      setInlineStatus(msg, 'error');
      void logToPanel(`Errore disconnessione: ${msg}`);
      setConnecting(false);
    }
    return;
  }
  const gateway = normalizeGatewayHost(gatewayEl.value);
  gatewayEl.value = gateway;
  const username = usernameEl.value.trim();
  const password = passwordEl.value;
  const port = parsePortFromUi();
  if (!gateway || !username || !password) {
    const parts = [];
    if (!gateway) parts.push('Gateway');
    if (!username) parts.push('Username');
    if (!password) parts.push('Password');
    const msg = `Compila tutti i campi (manca: ${parts.join(', ')}).`;
    setInlineStatus(msg, 'error');
    console.warn('[PoliVPN]', msg);
    return;
  }
  clearInlineStatus();
  statusText = 'Connessione in corso...';
  setConnecting(true);
  try {
    await invoke('connect', {
      payload: {
        gateway,
        port,
        username,
        password,
        realm: '',
        rememberCredentials: saveCredsCheck.checked,
      },
    });
  } catch (err) {
    const msg = formatInvokeError(err);
    statusText = '';
    setInlineStatus(msg, 'error');
    void logToPanel(`Errore connessione: ${msg}`);
    mainBtn.disabled = false;
    gatewayEl.disabled = false;
    portEl.disabled = false;
    usernameEl.disabled = false;
    passwordEl.disabled = false;
    syncPasswordToggleAvailability();
    setConnecting(false);
  }

}

vpnForm.addEventListener('submit', (e) => {
  void handleVpnFormSubmit(e);

});

logsBtn.addEventListener('click', async () => {
  try {
    await invoke('open_logs_window');
  } catch (err) {
    const msg = formatInvokeError(err);
    console.error('[PoliVPN] open_logs_window:', err);
    setInlineStatus(`Impossibile aprire i log: ${msg}`, 'error');
    void logToPanel(`Apertura finestra log fallita: ${msg}`);
  }

});

async function loadSavedCredentials() {
  try {
    const creds = await invoke('get_saved_credentials');
    if (creds?.username != null && String(creds.username).trim() !== '') {
      const user = String(creds.username).trim();
      gatewayEl.value = normalizeGatewayHost(String(creds.gateway || ''));
      const p = creds.port;
      if (p != null && p !== '') {
        const n = typeof p === 'number' ? p : Number.parseInt(String(p), 10);
        if (Number.isFinite(n) && n >= 1 && n <= 65535) {
          portEl.value = String(n);
        }
      }
      usernameEl.value = user;
      passwordEl.value = creds.password != null ? String(creds.password) : '';
      saveCredsCheck.checked = creds.rememberCredentials !== false;
      localStorage.setItem('polivpn_last_user', user);
    } else {
      saveCredsCheck.checked = true;
    }
  } catch (err) {
    const msg = formatInvokeError(err);
    console.warn('[PoliVPN] caricamento credenziali salvate:', msg);
    void logToPanel(`Caricamento credenziali salvate fallito: ${msg}`);
    saveCredsCheck.checked = true;
  }

}

/** Gateway/porta predefiniti da build MSI (sempre modificabili dall’utente). */

async function applyInstallDefaults() {
  try {
    const d = await invoke('get_install_defaults');
    if (d.gateway) {
      gatewayEl.value = normalizeGatewayHost(d.gateway);
    }
    if (d.port != null && d.port > 0) {
      portEl.value = String(d.port);
    }
    if (brandSubtitleEl && d.title != null && String(d.title).trim() !== '') {
      brandSubtitleEl.textContent = String(d.title);
    }
    if (logoEl && d.showLogo === false) {
      logoEl.hidden = true;
    }
  } catch (_) {
    /* offline / vecchia build */
  }

}

async function initUi() {
  await applyInstallDefaults();
  await loadSavedCredentials();
  await syncStatusFromBackend();

}

async function showAppVersion() {
  const el = document.getElementById('app-version');
  if (!el) return;
  try {
    const v = await invoke('app_version');
    el.textContent = `v${v}`;
  } catch (_) {
    el.textContent = '';
  }

}

gatewayEl.addEventListener('blur', () => {
  gatewayEl.value = normalizeGatewayHost(gatewayEl.value);

});

if (togglePasswordBtn) {
  togglePasswordBtn.addEventListener('click', () => {
    const showIcon = togglePasswordBtn.querySelector('.btn-toggle-password__icon--show');
    const hideIcon = togglePasswordBtn.querySelector('.btn-toggle-password__icon--hide');
    if (passwordEl.type === 'password') {
      passwordEl.type = 'text';
      togglePasswordBtn.setAttribute('aria-pressed', 'true');
      togglePasswordBtn.title = 'Nascondi password';
      togglePasswordBtn.setAttribute('aria-label', 'Nascondi password');
      if (showIcon && hideIcon) {
        showIcon.hidden = true;
        hideIcon.hidden = false;
      }
    } else {
      passwordEl.type = 'password';
      togglePasswordBtn.setAttribute('aria-pressed', 'false');
      togglePasswordBtn.title = 'Mostra password';
      togglePasswordBtn.setAttribute('aria-label', 'Mostra password');
      if (showIcon && hideIcon) {
        showIcon.hidden = false;
        hideIcon.hidden = true;
      }
    }
  });

}

let vpnCloseModalOnKeydown = null;

function detachVpnCloseModalKeydown() {
  if (vpnCloseModalOnKeydown != null) {
    document.removeEventListener('keydown', vpnCloseModalOnKeydown);
    vpnCloseModalOnKeydown = null;
  }
}

/** Ripristina pulsanti modale (fine flusso “disconnetti e chiudi”, chiusura normale, errore). */
function resetVpnCloseModalControls() {
  vpnCloseModalQuitFlowActive = false;
  if (vpnCloseBtnDisconnectQuit) {
    vpnCloseBtnDisconnectQuit.textContent = VPN_CLOSE_DISCONNECT_QUIT_LABEL;
    vpnCloseBtnDisconnectQuit.disabled = false;
  }
  for (const el of [
    vpnCloseBtnMoreOptions,
    vpnCloseBtnStay,
    vpnCloseBtnBack,
    vpnCloseBtnForceQuit,
  ]) {
    if (el) el.disabled = false;
  }
}

function setVpnCloseModalDisconnectPending(pending) {
  vpnCloseModalQuitFlowActive = pending;
  if (vpnCloseBtnDisconnectQuit) {
    vpnCloseBtnDisconnectQuit.textContent = pending ? 'Disconnessione...' : VPN_CLOSE_DISCONNECT_QUIT_LABEL;
    vpnCloseBtnDisconnectQuit.disabled = pending;
  }
  for (const el of [
    vpnCloseBtnMoreOptions,
    vpnCloseBtnStay,
    vpnCloseBtnBack,
    vpnCloseBtnForceQuit,
  ]) {
    if (el) el.disabled = pending;
  }
}

function hideVpnCloseModal(opts = {}) {
  const force = opts.force === true;
  if (vpnCloseModalQuitFlowActive && !force) return;
  detachVpnCloseModalKeydown();
  resetVpnCloseModalControls();
  if (vpnCloseModal) {
    vpnCloseModal.hidden = true;
  }
}

function vpnCloseModalShowStep1() {
  if (!vpnCloseModal || !vpnCloseModalStep1El || !vpnCloseModalStep2El) return;
  detachVpnCloseModalKeydown();
  resetVpnCloseModalControls();
  vpnCloseModalStep1El.hidden = false;
  vpnCloseModalStep2El.hidden = true;
  if (vpnCloseModalTitle) {
    vpnCloseModalTitle.textContent = 'Chiudi mentre sei connesso';
  }
  if (vpnCloseModalIntro) {
    vpnCloseModalIntro.textContent =
      'La VPN è ancora attiva. Vuoi disconnetterti prima di chiudere PoliVPN?';
  }
  vpnCloseModal.hidden = false;
  vpnCloseModalOnKeydown = (ev) => {
    if (ev.key !== 'Escape') return;
    if (vpnCloseModalQuitFlowActive) return;
    ev.preventDefault();
    hideVpnCloseModal();
  };
  document.addEventListener('keydown', vpnCloseModalOnKeydown);
  queueMicrotask(() => {
    vpnCloseBtnDisconnectQuit?.focus();
  });
}

function vpnCloseModalShowStep2() {
  if (!vpnCloseModalStep1El || !vpnCloseModalStep2El || !vpnCloseModalTitle || !vpnCloseModalForceWarning) {
    return;
  }
  vpnCloseModalStep1El.hidden = true;
  vpnCloseModalStep2El.hidden = false;
  vpnCloseModalTitle.textContent = 'Chiudere senza disconnettarti?';
  vpnCloseModalForceWarning.textContent =
    'Chiudendo ora, alcune route o impostazioni DNS della VPN possono restare applicate fino a quando non ti disconnetti o ricolleghi.';
  vpnCloseBtnForceQuit?.focus();

}

async function registerVpnCloseConfirmListener() {
  await listen('vpn-close-while-connected', () => {
    vpnCloseModalShowStep1();
  });
  vpnCloseModal?.addEventListener('click', (e) => {
    if (e.target !== vpnCloseModal) return;
    if (vpnCloseModalQuitFlowActive) return;
    hideVpnCloseModal();
  });
  vpnCloseBtnDisconnectQuit?.addEventListener('click', () => {
    void (async () => {
      setVpnCloseModalDisconnectPending(true);
      try {
        await invoke('disconnect');
      } catch (err) {
        const msg = formatInvokeError(err);
        void logToPanel(`Errore disconnessione in chiusura: ${msg}`);
      }
      try {
        await invoke('exit_app');
      } catch (e) {
        console.error('[PoliVPN] exit_app:', e);
        setVpnCloseModalDisconnectPending(false);
        return;
      }
      hideVpnCloseModal({ force: true });
    })();
  });
  vpnCloseBtnMoreOptions?.addEventListener('click', () => {
    vpnCloseModalShowStep2();
  });
  vpnCloseBtnForceQuit?.addEventListener('click', () => {
    void (async () => {
      try {
        await invoke('exit_app');
      } catch (e) {
        console.error('[PoliVPN] exit_app:', e);
        return;
      }
      hideVpnCloseModal();
    })();
  });
  vpnCloseBtnBack?.addEventListener('click', () => {
    vpnCloseModalShowStep1();
  });
  vpnCloseBtnStay?.addEventListener('click', () => {
    hideVpnCloseModal();
  });

}

async function boot() {
  await registerStatusListener();
  await registerVpnCloseConfirmListener();
  await initUi();
  await showAppVersion();

}

boot();
