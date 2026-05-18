const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const container = document.getElementById('logContainer');

function addEntry(timestamp, message, level) {
  const empty = container.querySelector('.empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = `log-entry ${level || ''}`;
  div.innerHTML = `<span class="timestamp">${timestamp}</span><span class="message">${message}</span>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;

  if (container.children.length > 1000) {
    container.removeChild(container.firstChild);
  }
}

// Load existing logs from backend
async function loadLogs() {
  try {
    const logs = await invoke('get_logs');
    if (logs && logs.length > 0) {
      const empty = container.querySelector('.empty');
      if (empty) empty.remove();
      for (const entry of logs) {
        addEntry(entry.timestamp, entry.message);
      }
    }
  } catch (_) {}
}

async function init() {
  await listen('vpn-log', (event) => {
    const { timestamp, message } = event.payload;
    addEntry(timestamp, message);
  });
  await loadLogs();
}

init();
