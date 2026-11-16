import React, { useState } from 'react';
import { api } from '../api.js';
import { Dot, group } from './ui.jsx';

function Invite({ state }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(state.card);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; the card stays selectable */
    }
  }

  return (
    <section className="glass p-4">
      <div className="flex items-center justify-between">
        <h2 className="label">Your contact card</h2>
        <button
          type="button"
          onClick={() => api.rotateInvite().catch(() => {})}
          title="Invalidate every card you have shared so far"
          data-testid="rotate-invite"
          className="text-[11px] text-zinc-500 transition hover:text-crimson"
        >
          Revoke
        </button>
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-zinc-500">
        Share it over a channel you already trust. It pins your identity and lets its holder connect.
      </p>
      <code
        data-testid="own-card"
        className="mt-3 block max-h-24 select-all overflow-y-auto break-all rounded-lg border border-white/[0.06] bg-black/40 p-2.5 font-mono text-[10.5px] leading-relaxed text-amethyst"
      >
        {state.card}
      </code>
      <button
        type="button"
        onClick={copy}
        className="mt-2 w-full rounded-lg border border-white/10 py-1.5 text-[12px] text-zinc-300 transition hover:border-cyan/40 hover:text-cyan"
      >
        {copied ? 'Copied' : 'Copy card'}
      </button>
    </section>
  );
}

function Connect({ onConnected }) {
  const [card, setCard] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { peer } = await api.connect(card.trim());
      setCard('');
      onConnected(peer);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="glass p-4">
      <label htmlFor="peer-card" className="label">
        Connect to a peer
      </label>
      <textarea
        id="peer-card"
        value={card}
        onChange={(e) => setCard(e.target.value)}
        placeholder="pqchat1:…"
        rows={3}
        maxLength={512}
        spellCheck={false}
        autoComplete="off"
        data-testid="peer-card-input"
        className="mt-3 block w-full resize-none rounded-lg border border-white/[0.08] bg-black/40 p-2.5 font-mono text-[11px] text-zinc-200 placeholder:text-zinc-700"
      />
      {error && (
        <p className="mt-2 text-[12px] text-crimson" role="alert" data-testid="connect-error">
          {error}
        </p>
      )}
      <button
        type="submit"
        disabled={busy || !card.trim()}
        data-testid="connect-button"
        className="mt-2 w-full rounded-lg bg-cyan py-1.5 text-[12px] font-semibold text-black transition hover:bg-cyan/90 disabled:cursor-not-allowed disabled:bg-white/[0.06] disabled:text-zinc-600"
      >
        {busy ? 'Handshaking…' : 'Connect'}
      </button>
    </form>
  );
}

export default function Sidebar({ state, selectedId, onSelect }) {
  return (
    <aside className="flex min-h-0 flex-col gap-4 overflow-y-auto">
      <section className="glass p-4">
        <h2 className="label">This node</h2>
        <p className="mt-2 text-[15px] font-medium text-white" data-testid="node-name">
          {state.name}
        </p>
        <p className="mt-0.5 font-mono text-[11px] text-zinc-500">{state.listen}</p>
        <p className="mt-3 font-mono text-[10.5px] leading-relaxed text-zinc-500" title="SHA-256 of your identity keys">
          {group(state.fingerprint)}
        </p>
      </section>

      <Invite state={state} />
      <Connect onConnected={onSelect} />

      {state.peers.length > 0 && (
        <section className="glass p-2">
          <h2 className="label px-2 pb-2 pt-2">Sessions</h2>
          <ul className="space-y-1" data-testid="peer-list">
            {state.peers.map((peer) => (
              <li key={peer.id}>
                <button
                  type="button"
                  onClick={() => onSelect(peer.id)}
                  aria-current={peer.id === selectedId}
                  data-testid="peer-item"
                  className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition ${
                    peer.id === selectedId ? 'border-cyan/30 bg-cyan/[0.05]' : 'border-transparent hover:bg-white/[0.04]'
                  }`}
                >
                  <Dot tone={peer.connected ? 'cyan' : 'neutral'} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[12px] text-zinc-200">{peer.id.slice(0, 16)}</span>
                    <span className="block text-[11px] text-zinc-500">
                      {peer.connected ? 'Encrypted session' : 'Disconnected'}
                      {peer.verified ? ' · verified' : ''}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </aside>
  );
}
