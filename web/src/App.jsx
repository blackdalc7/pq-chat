import React, { useEffect, useMemo, useState } from 'react';
import { openStream, takeToken } from './api.js';
import Chat from './components/Chat.jsx';
import CryptoPanel from './components/CryptoPanel.jsx';
import Sidebar from './components/Sidebar.jsx';
import { Dot, LockIcon } from './components/ui.jsx';

function Locked({ reason }) {
  return (
    <div className="flex h-screen items-center justify-center p-6" data-testid="locked">
      <div className="glass max-w-md p-8 text-center">
        <LockIcon className="mx-auto h-10 w-10 text-crimson" />
        <h1 className="mt-4 text-lg font-semibold text-white">This session is locked</h1>
        <p className="mt-2 text-[13px] leading-relaxed text-zinc-400">
          {reason} Open the link printed by <span className="font-mono text-zinc-300">python -m pqchat</span>. It carries a
          one-time access token for this browser tab.
        </p>
      </div>
    </div>
  );
}

export default function App() {
  const token = useMemo(takeToken, []);
  const [state, setState] = useState(null);
  const [status, setStatus] = useState('connecting');
  const [selectedId, setSelectedId] = useState(null);

  useEffect(() => (token ? openStream(setState, setStatus) : undefined), [token]);

  // Open an incoming session automatically when nothing is selected yet.
  const firstPeer = state?.peers[0]?.id;
  useEffect(() => {
    if (!selectedId && firstPeer) setSelectedId(firstPeer);
  }, [selectedId, firstPeer]);

  if (!token) return <Locked reason="No access token was provided." />;
  if (status === 'unauthorised') return <Locked reason="The access token was rejected." />;
  if (!state) return <div className="flex h-screen items-center justify-center text-[13px] text-zinc-600">Connecting to the local node…</div>;

  const peer = state.peers.find((p) => p.id === selectedId) || null;

  return (
    <div className="mx-auto flex h-screen max-w-[1600px] flex-col gap-4 p-5">
      <header className="flex items-center justify-between px-1">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-amethyst/30 bg-amethyst/10 p-2 text-amethyst">
            <LockIcon className="h-5 w-5" />
          </div>
          <div>
            <p className="text-[15px] font-semibold tracking-tight text-white">PQ-Chat</p>
            <p className="text-[12px] text-zinc-500">Serverless · hybrid post-quantum · end-to-end encrypted</p>
          </div>
        </div>
        <span className="flex items-center gap-2 text-[12px] text-zinc-500" data-testid="node-status">
          <Dot tone={status === 'online' ? 'cyan' : 'crimson'} pulse={status !== 'online'} />
          {status === 'online' ? 'Local node online' : 'Reconnecting to local node'}
        </span>
      </header>

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[290px_minmax(0,1fr)_350px]">
        <Sidebar state={state} selectedId={selectedId} onSelect={setSelectedId} />
        <Chat peer={peer} />
        <CryptoPanel state={state} peer={peer} />
      </div>
    </div>
  );
}
