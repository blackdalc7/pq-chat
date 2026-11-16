// The node prints a URL of the form http://127.0.0.1:PORT/#token=...
// The fragment is never sent over HTTP. It is read once, kept in
// sessionStorage (cleared when the tab closes) and removed from the address
// bar so it does not end up in history or a screenshot.
const KEY = 'pqchat.token';

export function takeToken() {
  const match = /(?:^#|&)token=([A-Za-z0-9_-]{32,})/.exec(window.location.hash);
  if (match) {
    sessionStorage.setItem(KEY, match[1]);
    window.history.replaceState(null, '', window.location.pathname);
  }
  return sessionStorage.getItem(KEY);
}

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${sessionStorage.getItem(KEY)}` },
    body: JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

export const api = {
  connect: (card) => post('/api/connect', { card }),
  send: (peer, text) => post('/api/send', { peer, text }),
  verify: (peer) => post('/api/verify', { peer }),
  rotateInvite: () => post('/api/invite/rotate'),
};

/** Opens the state stream. Calls onState for every snapshot, onStatus on changes. */
export function openStream(onState, onStatus) {
  let socket;
  let closed = false;
  let retry;

  const connect = () => {
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${window.location.host}/ws`);
    // First frame authenticates the socket; the server sends nothing before it.
    socket.onopen = () => socket.send(JSON.stringify({ token: sessionStorage.getItem(KEY) }));
    socket.onmessage = (event) => {
      onStatus('online');
      onState(JSON.parse(event.data));
    };
    socket.onclose = (event) => {
      if (closed) return;
      if (event.code === 4401) {
        onStatus('unauthorised');
        return;
      }
      onStatus('offline');
      retry = setTimeout(connect, 1500);
    };
  };
  connect();

  return () => {
    closed = true;
    clearTimeout(retry);
    socket?.close();
  };
}
