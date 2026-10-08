/**
 * Surveillance Operations Center (NVR/VMS Console) - Client Engine
 * App Version: v1.0.1
 * Standards: WebRTC PeerConnection via go2rtc, WebSocket/SSE Alerts, Universal Search
 */

(function () {
  'use strict';

  const APP_VERSION = 'v1.0.1';
  console.log(`[NVR Console] Phiên bản: ${APP_VERSION} initialized.`);

  // Core State
  const state = {
    cameras: [],
    accounts: [],
    activeSlots: {}, // slotIndex -> camera_id
    selectedCameraId: null,
    currentGridLayout: '1x1',
    activeRecordings: {}, // camera_id -> { recording_id, startTime, timerInterval }
    peerConnections: {}, // slotIndex -> RTCPeerConnection
    eventFilter: 'all',
    searchQuery: '',
    unreadEventsCount: 0,
    wsConnected: false,
    audioContext: null,
  };

  // Dom Elements
  const dom = {
    cameraGrid: document.getElementById('camera-grid'),
    cameraChannelList: document.getElementById('camera-channel-list'),
    countCameras: document.getElementById('count-cameras'),
    ptzTargetName: document.getElementById('ptz-target-name'),
    ptzSpeedSlider: document.getElementById('ptz-speed-slider'),
    ptzSpeedVal: document.getElementById('ptz-speed-val'),
    eventTableBody: document.getElementById('event-table-body'),
    eventSearchInput: document.getElementById('event-search-input'),
    unreadEventBadge: document.getElementById('unread-event-badge'),
    toastContainer: document.getElementById('toast-container'),
    gatewayStatus: document.getElementById('gateway-status'),
    wsStatus: document.getElementById('ws-status'),
  };

  // --------------------------------------------------------------------------
  // Audio Synthesis for Alarms (Web Audio API - Zero Asset Dependency)
  // --------------------------------------------------------------------------
  function playAlertChime(eventType) {
    try {
      if (!state.audioContext) {
        state.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (state.audioContext.state === 'suspended') {
        state.audioContext.resume();
      }
      const ctx = state.audioContext;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      // Distinguish pitch by event type
      const baseFreq = eventType === 'Human' ? 880 : eventType === 'Abnormal Sound' ? 1200 : 660;
      osc.frequency.setValueAtTime(baseFreq, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(baseFreq * 1.5, ctx.currentTime + 0.15);

      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } catch (e) {
      console.warn('Audio chime playback omitted:', e);
    }
  }

  // --------------------------------------------------------------------------
  // Toast Notifications
  // --------------------------------------------------------------------------
  function showToast({ title, message, type = 'info', thumbnail = null, timeout = 5000 }) {
    const toast = document.createElement('div');
    toast.className = 'toast-item';

    let iconColor = 'text-blue-400';
    let borderColor = 'border-white/10';
    if (type === 'Human') {
      iconColor = 'text-amber-400';
      borderColor = 'border-amber-500/40';
    } else if (type === 'Movement') {
      iconColor = 'text-cyan-400';
      borderColor = 'border-cyan-500/40';
    } else if (type === 'Abnormal Sound') {
      iconColor = 'text-fuchsia-400';
      borderColor = 'border-fuchsia-500/40';
    }

    toast.style.borderColor = borderColor;

    const imgHtml = thumbnail
      ? `<img src="${thumbnail}" class="w-12 h-12 object-cover rounded border border-white/20 shrink-0 cursor-pointer" onclick="openLightbox('${thumbnail}', '${title}')">`
      : `<div class="w-9 h-9 rounded-lg bg-surface-dark border border-white/10 flex items-center justify-center shrink-0 ${iconColor}">
          <svg class="w-5 h-5" width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>`;

    toast.innerHTML = `
      ${imgHtml}
      <div class="flex-1 overflow-hidden">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold text-slate-100 truncate">${title}</span>
          <span class="text-[10px] text-slate-400 font-mono">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="text-[11px] text-slate-300 truncate mt-0.5">${message}</div>
      </div>
      <button class="text-slate-400 hover:text-white text-sm shrink-0 ml-1" onclick="this.parentElement.remove()">&times;</button>
    `;

    dom.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, timeout);
  }

  // --------------------------------------------------------------------------
  // WebRTC Stream Negotiation (go2rtc WHEP / SDP Protocol)
  // --------------------------------------------------------------------------
  const getGo2rtcUrl = () => {
    const host = window.location.hostname || '127.0.0.1';
    return `http://${host}:1984`;
  };

  async function connectWebRTC(cameraId, videoElement, osdElement) {
    if (!cameraId || !videoElement) return;

    const go2rtcBase = getGo2rtcUrl();

    // Check if browser supports WebRTC
    if (!window.RTCPeerConnection) {
      console.warn('Browser does not support RTCPeerConnection, falling back to MSE');
      videoElement.src = `${go2rtcBase}/api/stream.mp4?src=${encodeURIComponent(cameraId)}`;
      videoElement.play().catch(() => {});
      return;
    }

    const pc = new RTCPeerConnection({
      iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }],
    });

    pc.addTransceiver('video', { direction: 'recvonly' });
    pc.addTransceiver('audio', { direction: 'recvonly' });

    pc.ontrack = (event) => {
      if (event.streams && event.streams[0]) {
        videoElement.srcObject = event.streams[0];
      } else {
        const inboundStream = new MediaStream([event.track]);
        videoElement.srcObject = inboundStream;
      }
      videoElement.play().catch(() => {});
    };

    // Telemetry stats monitoring
    let statsTimer = setInterval(async () => {
      if (!pc || pc.connectionState === 'closed') {
        clearInterval(statsTimer);
        return;
      }
      try {
        const stats = await pc.getStats();
        let fps = 0, bytesReceived = 0;
        stats.forEach((report) => {
          if (report.type === 'inbound-rtp' && report.kind === 'video') {
            fps = report.framesPerSecond || 0;
            bytesReceived = report.bytesReceived || 0;
          }
        });
        if (osdElement) {
          osdElement.textContent = `${fps ? fps.toFixed(0) : '25'} FPS | ${(bytesReceived / 1024 / 1024).toFixed(1)} MB | WebRTC LIVE`;
        }
      } catch (e) {}
    }, 2000);

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      // Exchange SDP with go2rtc WebRTC gateway
      const response = await fetch(`${go2rtcBase}/api/webrtc?src=${encodeURIComponent(cameraId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/sdp' },
        body: offer.sdp,
      });

      if (!response.ok) {
        throw new Error(`go2rtc SDP exchange failed: HTTP ${response.status}`);
      }

      const answerSdp = await response.text();
      await pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: answerSdp }));
      return pc;
    } catch (err) {
      console.warn(`WebRTC error for ${cameraId}, falling back to MSE:`, err);
      // Fallback to go2rtc fMP4 stream
      videoElement.src = `${go2rtcBase}/api/stream.mp4?src=${encodeURIComponent(cameraId)}`;
      videoElement.play().catch(() => {});
      if (osdElement) osdElement.textContent = 'MSE Stream Active';
      return null;
    }
  }

  // --------------------------------------------------------------------------
  // Camera Grid Rendering
  // --------------------------------------------------------------------------
  function getSlotCount(layout) {
    switch (layout) {
      case '1x1': return 1;
      case '2x2': return 4;
      case '3x3': return 9;
      case '4x4': return 16;
      case '1+5': return 6;
      default: return 4;
    }
  }

  function renderGrid() {
    const slotCount = getSlotCount(state.currentGridLayout);
    dom.cameraGrid.className = `grid-container grid-${state.currentGridLayout} w-full h-full flex-1 gap-2`;

    // Clear existing tiles and close old WebRTC connections
    Object.values(state.peerConnections).forEach(pc => pc && pc.close && pc.close());
    state.peerConnections = {};
    dom.cameraGrid.innerHTML = '';

    for (let i = 0; i < slotCount; i++) {
      const cameraId = state.activeSlots[i] || (state.cameras[i] ? state.cameras[i].id : null);
      const cam = state.cameras.find(c => c.id === cameraId);
      const isSelected = state.selectedCameraId === cameraId;
      const isRecording = cameraId && !!state.activeRecordings[cameraId];

      const tile = document.createElement('div');
      tile.className = `camera-tile ${isSelected ? 'selected' : ''} ${isRecording ? 'recording' : ''}`;
      tile.dataset.slotIndex = i;
      tile.dataset.cameraId = cameraId || '';

      if (cam) {
        tile.innerHTML = `
          <div class="tile-header">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span class="text-xs font-bold text-slate-100 truncate max-w-[140px]">${cam.name}</span>
              <span class="text-[10px] px-1 py-0.2 rounded bg-surface-card text-slate-400 font-mono border border-white/5 uppercase">${cam.vendor || 'IP'}</span>
            </div>
            <div class="flex items-center gap-1.5">
              ${isRecording ? '<span class="px-1.5 py-0.5 rounded bg-red-600 text-[10px] font-bold text-white uppercase tracking-wider animate-pulse flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-white"></span>REC</span>' : ''}
              <span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30 uppercase">LIVE</span>
            </div>
          </div>

          <video autoplay playsinline muted></video>

          <div class="tile-osd">Đang kết nối luồng...</div>

          <div class="tile-actions">
            <button class="tile-btn btn-snapshot" title="Chụp ảnh Snapshot" onclick="window.NVR.takeSnapshot('${cam.id}')">
              <svg class="w-3.5 h-3.5 text-blue-400" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"></path></svg>
            </button>
            <button class="tile-btn btn-rec ${isRecording ? 'active' : ''}" title="${isRecording ? 'Dừng ghi hình' : 'Ghi hình thời gian thực'}" onclick="window.NVR.toggleRecord('${cam.id}')">
              <span class="w-2 h-2 rounded-full ${isRecording ? 'bg-white' : 'bg-red-500'}"></span>
              <span>${isRecording ? 'Dừng' : 'Ghi'}</span>
            </button>
            <button class="tile-btn btn-ptz" title="Mở điều khiển PTZ" onclick="window.NVR.selectCamera('${cam.id}', true)">
              <svg class="w-3.5 h-3.5 text-yellow-400" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7l4-4m0 0l4 4m-4-4v18m-7-7l-4-4m0 0l4-4m-4 4h18"></path></svg>
            </button>
            <button class="tile-btn btn-single" title="Phóng to kênh này" onclick="window.NVR.toggleFocusSlot(${i})">
              <svg class="w-3.5 h-3.5 text-slate-300" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"></path></svg>
            </button>
          </div>
        `;

        tile.addEventListener('click', (e) => {
          if (!e.target.closest('button')) {
            window.NVR.selectCamera(cam.id);
          }
        });

        const video = tile.querySelector('video');
        const osd = tile.querySelector('.tile-osd');
        connectWebRTC(cam.id, video, osd).then(pc => {
          if (pc) state.peerConnections[i] = pc;
        });
      } else {
        // Empty Tile Placeholder
        tile.innerHTML = `
          <div class="flex-1 flex flex-col items-center justify-center text-slate-600 gap-2 p-4">
            <svg class="w-10 h-10 opacity-40" width="40" height="40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
            </svg>
            <span class="text-xs font-medium">Kênh trống #${i + 1}</span>
            <button class="text-[11px] text-blue-400 hover:text-blue-300 underline" onclick="document.getElementById('btn-open-devices').click()">+ Thêm Camera</button>
          </div>
        `;
      }

      dom.cameraGrid.appendChild(tile);
    }
  }

  // --------------------------------------------------------------------------
  // Camera Channel List
  // --------------------------------------------------------------------------
  function renderChannelList() {
    dom.countCameras.textContent = state.cameras.length;
    dom.cameraChannelList.innerHTML = '';

    if (state.cameras.length === 0) {
      dom.cameraChannelList.innerHTML = `
        <div class="text-xs text-slate-500 italic text-center py-6">
          Chưa có camera nào. Nhấn "+ Thêm Thiết bị / Cloud" để bắt đầu.
        </div>
      `;
      return;
    }

    state.cameras.forEach((cam, idx) => {
      const item = document.createElement('div');
      item.className = `p-2.5 rounded-lg border border-white/5 bg-surface-dark/60 hover:bg-surface-card flex items-center justify-between cursor-pointer transition ${state.selectedCameraId === cam.id ? 'border-blue-500/60 bg-surface-card' : ''}`;
      item.innerHTML = `
        <div class="flex items-center gap-2.5 overflow-hidden">
          <div class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></div>
          <div class="truncate">
            <div class="text-xs font-bold text-slate-200 truncate">${cam.name}</div>
            <div class="text-[10px] text-slate-400 font-mono truncate">${cam.vendor || 'Generic'} • ${cam.ip_address || 'Cloud'}</div>
          </div>
        </div>
        <div class="flex items-center gap-1 shrink-0">
          <button class="p-1 hover:text-blue-400 text-slate-400" title="Xem trên ô đầu tiên" onclick="event.stopPropagation(); window.NVR.assignCameraToSlot(0, '${cam.id}')">
            <svg class="w-3.5 h-3.5" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          </button>
        </div>
      `;
      item.addEventListener('click', () => {
        window.NVR.selectCamera(cam.id);
      });
      dom.cameraChannelList.appendChild(item);
    });
  }

  // --------------------------------------------------------------------------
  // PTZ Control Engine
  // --------------------------------------------------------------------------
  async function sendPTZ(command, direction = null) {
    if (!state.selectedCameraId) {
      showToast({ title: 'PTZ', message: 'Vui lòng chọn một camera để điều khiển PTZ.', type: 'info' });
      return;
    }

    const speed = parseInt(dom.ptzSpeedSlider.value, 10) || 5;
    try {
      if (command === 'stop') {
        await fetch(`/api/cameras/${encodeURIComponent(state.selectedCameraId)}/ptz/stop`, {
          method: 'POST',
        });
      } else {
        await fetch(`/api/cameras/${encodeURIComponent(state.selectedCameraId)}/ptz`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            command: 'start',
            direction: direction,
            speed: speed,
          }),
        });
      }
    } catch (err) {
      console.warn('PTZ command error:', err);
    }
  }

  function setupPTZButtons() {
    document.querySelectorAll('.ptz-btn').forEach(btn => {
      const cmd = btn.dataset.cmd;
      const startAction = (e) => {
        e.preventDefault();
        sendPTZ('start', cmd);
      };
      const stopAction = (e) => {
        e.preventDefault();
        sendPTZ('stop');
      };

      btn.addEventListener('mousedown', startAction);
      btn.addEventListener('mouseup', stopAction);
      btn.addEventListener('mouseleave', stopAction);
      btn.addEventListener('touchstart', startAction, { passive: false });
      btn.addEventListener('touchend', stopAction);
    });

    const stopBtn = document.querySelector('.ptz-btn-stop');
    if (stopBtn) {
      stopBtn.addEventListener('click', () => sendPTZ('stop'));
    }

    dom.ptzSpeedSlider.addEventListener('input', (e) => {
      dom.ptzSpeedVal.textContent = e.target.value;
    });
  }

  // --------------------------------------------------------------------------
  // Real-Time Event System (WebSocket & SSE Pipeline)
  // --------------------------------------------------------------------------
  function connectAlertWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/ws/events`;

    try {
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        state.wsConnected = true;
        dom.wsStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span><span>WS: Trực tuyến</span>';
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'NEW_EVENT' && payload.data) {
            handleIncomingEvent(payload.data);
          }
        } catch (e) {}
      };

      ws.onclose = () => {
        state.wsConnected = false;
        dom.wsStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span><span>WS: Đang kết nối lại...</span>';
        setTimeout(connectAlertWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (e) {
      console.warn('WebSocket connection error, starting SSE fallback:', e);
      connectAlertSSE();
    }
  }

  function connectAlertSSE() {
    try {
      const evtSource = new EventSource('/api/events/stream');
      evtSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'NEW_EVENT' && payload.data) {
            handleIncomingEvent(payload.data);
          }
        } catch (e) {}
      };
    } catch (e) {}
  }

  function handleIncomingEvent(data) {
    state.unreadEventsCount++;
    dom.unreadEventBadge.textContent = state.unreadEventsCount;
    dom.unreadEventBadge.classList.remove('hidden');

    playAlertChime(data.event_type);

    showToast({
      title: `${data.event_type} Cảnh Báo`,
      message: `${data.camera_name || 'Camera'}: Phát hiện lúc ${new Date(data.timestamp).toLocaleTimeString()}`,
      type: data.event_type,
      thumbnail: data.snapshot_url || null,
    });

    renderEventRow(data, true);
  }

  function renderEventRow(item, prepend = false) {
    const row = document.createElement('tr');
    row.className = 'hover:bg-white/5 transition';

    let badgeClass = 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    if (item.event_type === 'Human') badgeClass = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    else if (item.event_type === 'Movement') badgeClass = 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
    else if (item.event_type === 'Abnormal Sound') badgeClass = 'bg-fuchsia-500/15 text-fuchsia-400 border-fuchsia-500/30';

    const timeStr = new Date(item.timestamp).toLocaleTimeString();
    const snapBtn = item.snapshot_url
      ? `<button class="p-1 text-blue-400 hover:text-white" onclick="openLightbox('${item.snapshot_url}', '${item.camera_name}')">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
        </button>`
      : '-';

    row.innerHTML = `
      <td class="py-2 px-2.5 text-slate-300 whitespace-nowrap text-[11px]">${timeStr}</td>
      <td class="py-2 px-2"><span class="px-1.5 py-0.5 rounded text-[10px] border ${badgeClass} font-semibold">${item.event_type}</span></td>
      <td class="py-2 px-2 text-slate-200 truncate max-w-[90px] font-medium">${item.camera_name || 'Cam'}</td>
      <td class="py-2 px-2 text-center">${snapBtn}</td>
    `;

    if (prepend && dom.eventTableBody.firstChild) {
      dom.eventTableBody.insertBefore(row, dom.eventTableBody.firstChild);
    } else {
      dom.eventTableBody.appendChild(row);
    }
  }

  async function loadInitialEvents() {
    try {
      const res = await fetch('/api/events?page=1&page_size=50');
      if (res.ok) {
        const events = await res.json();
        dom.eventTableBody.innerHTML = '';
        events.forEach(item => renderEventRow(item, false));
      }
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // 3-Mode Export (DTCS2 Rule)
  // --------------------------------------------------------------------------
  function triggerExport(mode, format = 'csv') {
    let url = `/api/events/export?mode=${encodeURIComponent(mode)}&format=${encodeURIComponent(format)}`;
    if (mode === 'filtered') {
      if (state.searchQuery) url += `&query=${encodeURIComponent(state.searchQuery)}`;
      if (state.eventFilter !== 'all') url += `&event_type=${encodeURIComponent(state.eventFilter)}`;
    }
    window.open(url, '_blank');
  }

  // --------------------------------------------------------------------------
  // Core Actions API (NVR Namespace)
  // --------------------------------------------------------------------------
  window.NVR = {
    selectCamera: (cameraId, switchTab = false) => {
      state.selectedCameraId = cameraId;
      const cam = state.cameras.find(c => c.id === cameraId);
      dom.ptzTargetName.textContent = cam ? cam.name : cameraId;

      // Highlight selected tile
      document.querySelectorAll('.camera-tile').forEach(t => {
        if (t.dataset.cameraId === cameraId) t.classList.add('selected');
        else t.classList.remove('selected');
      });

      if (switchTab) {
        document.querySelector('[data-tab="tab-ptz"]').click();
      }
    },

    assignCameraToSlot: (slotIdx, cameraId) => {
      state.activeSlots[slotIdx] = cameraId;
      renderGrid();
    },

    toggleFocusSlot: (slotIdx) => {
      if (state.currentGridLayout === '1x1') {
        state.currentGridLayout = '2x2';
      } else {
        const targetCam = state.activeSlots[slotIdx] || (state.cameras[slotIdx] ? state.cameras[slotIdx].id : null);
        state.activeSlots[0] = targetCam;
        state.currentGridLayout = '1x1';
      }
      document.querySelectorAll('.grid-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.grid === state.currentGridLayout);
      });
      renderGrid();
    },

    takeSnapshot: async (cameraId) => {
      try {
        const res = await fetch(`/api/snapshots/${encodeURIComponent(cameraId)}`, { method: 'POST' });
        if (!res.ok) throw new Error('Lỗi chụp ảnh');
        const data = await res.json();
        showToast({
          title: 'Chụp Ảnh Thành Công',
          message: `${data.filename} (${(data.size_bytes / 1024).toFixed(0)} KB)`,
          thumbnail: data.url,
          timeout: 4000,
        });
      } catch (e) {
        showToast({ title: 'Chụp Ảnh Thất Bại', message: e.message, type: 'error' });
      }
    },

    toggleRecord: async (cameraId) => {
      if (state.activeRecordings[cameraId]) {
        // Stop recording
        const rec = state.activeRecordings[cameraId];
        try {
          await fetch(`/api/recordings/stop/${encodeURIComponent(rec.recording_id)}`, { method: 'POST' });
          delete state.activeRecordings[cameraId];
          showToast({ title: 'Ghi Hình', message: 'Đã dừng ghi hình và lưu tệp MP4.' });
          renderGrid();
        } catch (e) {
          showToast({ title: 'Lỗi Dừng Ghi', message: e.message, type: 'error' });
        }
      } else {
        // Start recording
        try {
          const res = await fetch('/api/recordings/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ camera_id: cameraId, mode: 'manual' }),
          });
          if (!res.ok) throw new Error('Lỗi bắt đầu ghi hình');
          const data = await res.json();
          state.activeRecordings[cameraId] = {
            recording_id: data.id,
            startTime: Date.now(),
          };
          showToast({ title: 'Ghi Hình', message: 'Đang ghi hình thời gian thực (fMP4)...' });
          renderGrid();
        } catch (e) {
          showToast({ title: 'Lỗi Ghi Hình', message: e.message, type: 'error' });
        }
      }
    },
  };

  // --------------------------------------------------------------------------
  // Data Fetching & Sync
  // --------------------------------------------------------------------------
  async function loadCameras() {
    try {
      const res = await fetch('/api/cameras');
      if (res.ok) {
        state.cameras = await res.json();
        renderChannelList();
        renderGrid();
      }
    } catch (e) {
      console.warn('Lỗi tải danh sách camera:', e);
    }
  }

  async function loadAccounts() {
    try {
      const res = await fetch('/api/accounts');
      if (res.ok) {
        state.accounts = await res.json();
      }
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // UI Event Handlers
  // --------------------------------------------------------------------------
  function setupUIHandlers() {
    // Grid switcher buttons
    document.querySelectorAll('.grid-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.grid-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.currentGridLayout = btn.dataset.grid;
        renderGrid();
      });
    });

    // Side panel tabs
    document.querySelectorAll('.panel-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.panel-tab').forEach(t => {
          t.classList.remove('active', 'border-blue-500', 'text-blue-400');
          t.classList.add('border-transparent', 'text-slate-400');
        });
        tab.classList.add('active', 'border-blue-500', 'text-blue-400');
        tab.classList.remove('border-transparent', 'text-slate-400');

        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        document.getElementById(tab.dataset.tab).classList.remove('hidden');
      });
    });

    // Event filter chips
    document.querySelectorAll('.event-filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.event-filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        state.eventFilter = chip.dataset.type;
        filterEventTable();
      });
    });

    // Universal Search Input
    dom.eventSearchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.toLowerCase();
      filterEventTable();
    });

    // Export buttons
    document.getElementById('btn-export-template').addEventListener('click', () => triggerExport('template'));
    document.getElementById('btn-export-filtered').addEventListener('click', () => triggerExport('filtered'));
    document.getElementById('btn-export-all').addEventListener('click', () => triggerExport('all'));

    // Toggle events button in header
    document.getElementById('btn-toggle-events').addEventListener('click', () => {
      document.querySelector('[data-tab="tab-events"]').click();
      state.unreadEventsCount = 0;
      dom.unreadEventBadge.classList.add('hidden');
    });

    // Modals
    const modalDevices = document.getElementById('modal-devices');
    const modalGallery = document.getElementById('modal-gallery');

    document.getElementById('btn-open-devices').addEventListener('click', () => {
      modalDevices.classList.remove('hidden');
    });

    document.getElementById('btn-open-gallery').addEventListener('click', () => {
      modalGallery.classList.remove('hidden');
      loadGallery();
    });

    document.querySelectorAll('.modal-close, .modal-backdrop').forEach(el => {
      el.addEventListener('click', (e) => {
        if (e.target === el) {
          el.closest('.modal-backdrop').classList.add('hidden');
        }
      });
    });

    // Modal subtabs
    document.querySelectorAll('.modal-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.modal-tab').forEach(t => {
          t.classList.remove('active', 'border-blue-500', 'text-blue-400');
          t.classList.add('border-transparent', 'text-slate-400');
        });
        tab.classList.add('active', 'border-blue-500', 'text-blue-400');
        tab.classList.remove('border-transparent', 'text-slate-400');

        document.querySelectorAll('.subtab-content').forEach(c => c.classList.add('hidden'));
        document.getElementById(tab.dataset.subtab).classList.remove('hidden');
      });
    });

    // Form Submissions
    document.getElementById('form-ezviz').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const payload = {
        name: formData.get('name'),
        provider: 'ezviz',
        credentials: {
          app_key: formData.get('app_key'),
          app_secret: formData.get('app_secret'),
        },
      };
      await saveAccount(payload, modalDevices);
    });

    document.getElementById('form-xiaomi').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const payload = {
        name: formData.get('name'),
        provider: 'xiaomi',
        credentials: {
          username: formData.get('username'),
          password: formData.get('password'),
          server_region: formData.get('server_region'),
        },
      };
      await saveAccount(payload, modalDevices);
    });

    document.getElementById('form-rtsp').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const payload = {
        name: formData.get('name'),
        vendor: formData.get('vendor') || 'generic',
        mainstream_url: formData.get('mainstream_url'),
        substream_url: formData.get('substream_url') || null,
      };
      try {
        const res = await fetch('/api/cameras', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) {
          showToast({ title: 'Thêm Camera', message: 'Camera RTSP đã được kết nối thành công!' });
          modalDevices.classList.add('hidden');
          loadCameras();
        }
      } catch (err) {
        showToast({ title: 'Lỗi', message: err.message, type: 'error' });
      }
    });

    // ONVIF Discovery
    document.getElementById('btn-run-discover').addEventListener('click', async () => {
      const listEl = document.getElementById('discovered-list');
      listEl.innerHTML = '<div class="text-blue-400 text-center py-8 animate-pulse">Đang gửi gói tin UDP Multicast quét camera trên mạng LAN...</div>';
      try {
        const res = await fetch('/api/cameras/discover', { method: 'POST' });
        if (res.ok) {
          const items = await res.json();
          if (items.length === 0) {
            listEl.innerHTML = '<div class="text-slate-500 italic text-center py-8">Không tìm thấy thiết bị ONVIF nào trong mạng. Vui lòng thêm bằng luồng RTSP thủ công.</div>';
          } else {
            listEl.innerHTML = '';
            items.forEach(d => {
              const div = document.createElement('div');
              div.className = 'p-2 bg-surface-dark rounded border border-white/10 flex items-center justify-between';
              div.innerHTML = `
                <div>
                  <div class="font-bold text-slate-200">${d.name || d.ip}</div>
                  <div class="text-[10px] text-slate-400 font-mono">${d.xaddr || d.ip}</div>
                </div>
                <button class="px-2 py-1 bg-blue-600 text-white rounded text-xs" onclick="addDiscoveredCam('${d.ip}', '${d.xaddr}')">Kết Nối</button>
              `;
              listEl.appendChild(div);
            });
          }
        }
      } catch (e) {
        listEl.innerHTML = `<div class="text-red-400 text-center py-8">Lỗi quét ONVIF: ${e.message}</div>`;
      }
    });

    // Fullscreen toggle
    document.getElementById('btn-fullscreen').addEventListener('click', () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
      } else {
        document.exitFullscreen().catch(() => {});
      }
    });

    // Sync all
    document.getElementById('btn-sync-all').addEventListener('click', async () => {
      showToast({ title: 'Đồng bộ', message: 'Đang tải lại danh sách camera từ cloud...' });
      await fetch('/api/cameras/sync', { method: 'POST' });
      await loadCameras();
    });
  }

  async function saveAccount(payload, modal) {
    try {
      const res = await fetch('/api/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const account = await res.json();
        showToast({ title: 'Tài Khoản', message: 'Lưu tài khoản thành công! Đang đồng bộ danh sách camera...' });
        modal.classList.add('hidden');
        // Trigger sync
        await fetch(`/api/accounts/${account.id}/sync`, { method: 'POST' });
        await loadCameras();
      } else {
        const err = await res.json();
        showToast({ title: 'Lỗi', message: err.detail || 'Không thể lưu tài khoản', type: 'error' });
      }
    } catch (e) {
      showToast({ title: 'Lỗi', message: e.message, type: 'error' });
    }
  }

  function filterEventTable() {
    const rows = dom.eventTableBody.querySelectorAll('tr');
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      const matchSearch = !state.searchQuery || text.includes(state.searchQuery);
      const matchType = state.eventFilter === 'all' || text.includes(state.eventFilter.toLowerCase());
      row.style.display = (matchSearch && matchType) ? '' : 'none';
    });
  }

  async function loadGallery() {
    const container = document.getElementById('gallery-grid');
    container.innerHTML = '<div class="col-span-3 text-center text-slate-500 py-8">Đang tải dữ liệu...</div>';
    try {
      const [recRes, snapRes] = await Promise.all([
        fetch('/api/recordings'),
        fetch('/api/snapshots'),
      ]);
      const recordings = recRes.ok ? await recRes.json() : [];
      const snapshots = snapRes.ok ? await snapRes.json() : [];

      container.innerHTML = '';
      if (recordings.length === 0 && snapshots.length === 0) {
        container.innerHTML = '<div class="col-span-3 text-center text-slate-500 py-8">Chưa có bản ghi hoặc ảnh chụp nào.</div>';
        return;
      }

      snapshots.forEach(s => {
        const card = document.createElement('div');
        card.className = 'bg-surface-dark border border-white/10 rounded-lg overflow-hidden flex flex-col';
        card.innerHTML = `
          <img src="${s.url}" class="w-full h-32 object-cover cursor-pointer hover:opacity-90" onclick="openLightbox('${s.url}', '${s.filename}')">
          <div class="p-2 text-xs flex flex-col gap-1">
            <span class="font-bold text-slate-200 truncate">${s.filename}</span>
            <span class="text-[10px] text-slate-400 font-mono">${(s.size_bytes / 1024).toFixed(0)} KB • Snapshot</span>
            <a href="${s.url}" download class="text-[11px] text-blue-400 hover:underline">Tải về</a>
          </div>
        `;
        container.appendChild(card);
      });

      recordings.forEach(r => {
        const card = document.createElement('div');
        card.className = 'bg-surface-dark border border-white/10 rounded-lg overflow-hidden flex flex-col';
        card.innerHTML = `
          <div class="w-full h-32 bg-black flex items-center justify-center text-slate-500">
            <svg class="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path></svg>
          </div>
          <div class="p-2 text-xs flex flex-col gap-1">
            <span class="font-bold text-slate-200 truncate">${r.filename || r.id}</span>
            <span class="text-[10px] text-slate-400 font-mono">Video MP4 • ${r.duration_seconds || 0}s</span>
            <a href="${r.url || '/recordings/' + r.filename}" download class="text-[11px] text-blue-400 hover:underline">Tải về</a>
          </div>
        `;
        container.appendChild(card);
      });
    } catch (e) {
      container.innerHTML = `<div class="col-span-3 text-center text-red-400 py-8">Lỗi tải thư viện: ${e.message}</div>`;
    }
  }

  window.openLightbox = (src, caption) => {
    const lb = document.getElementById('modal-lightbox');
    document.getElementById('lightbox-img').src = src;
    document.getElementById('lightbox-caption').textContent = caption || '';
    lb.classList.remove('hidden');
  };

  // --------------------------------------------------------------------------
  // Application Bootstrap
  // --------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', async () => {
    setupUIHandlers();
    setupPTZButtons();
    connectAlertWebSocket();
    await loadCameras();
    await loadAccounts();
    await loadInitialEvents();
  });
})();
