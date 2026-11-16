import React, { useEffect, useRef, useState } from 'react';
import { api } from '../api.js';
import { LockIcon } from './ui.jsx';

const time = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function Message({ message }) {
  const mine = message.direction === 'out';
  return (
    <li className={`flex ${mine ? 'justify-end' : 'justify-start'}`} data-testid="message" data-direction={message.direction}>
      <div className="max-w-[72%]">
        {/* Rendered as text by React: message content is never treated as HTML. */}
        <p
          className={`whitespace-pre-wrap break-words rounded-2xl border px-3.5 py-2 text-[14px] leading-relaxed ${
            mine ? 'rounded-br-md border-cyan/25 bg-cyan/[0.08] text-zinc-100' : 'rounded-bl-md border-white/[0.08] bg-white/[0.04] text-zinc-200'
          }`}
        >
          {message.text}
        </p>
        <p className={`mt-1 font-mono text-[10px] text-zinc-600 ${mine ? 'text-right' : ''}`}>
          {time(message.ts)} · key <span className="text-amethyst/80" data-testid="message-key">{message.key_tag}</span> · epoch{' '}
          {message.epoch} #{message.n}
        </p>
      </div>
    </li>
  );
}

export default function Chat({ peer }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const bottom = useRef(null);
  const count = peer?.messages.length ?? 0;

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' });
  }, [count, peer?.id]);

  if (!peer) {
    return (
      <section className="glass flex flex-col items-center justify-center px-8 text-center" data-testid="chat-empty">
        <LockIcon className="h-9 w-9 text-zinc-700" />
        <p className="mt-4 text-[15px] font-medium text-zinc-200">No conversation open</p>
        <p className="mt-1.5 max-w-sm text-[13px] leading-relaxed text-zinc-500">
          Paste a peer&apos;s contact card to open a direct, end-to-end encrypted session. Nothing is relayed or stored by a server.
        </p>
      </section>
    );
  }

  const ready = peer.connected && peer.ratchet.can_send;

  async function submit(event) {
    event.preventDefault();
    const text = draft.trim();
    if (!text) return;
    setError('');
    try {
      await api.send(peer.id, text);
      setDraft('');
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <section className="glass flex min-h-0 flex-col" data-testid="chat">
      <header className="flex items-center justify-between border-b border-white/[0.06] px-5 py-3.5">
        <div>
          <p className="font-mono text-[13px] text-zinc-100">{peer.id.slice(0, 24)}</p>
          <p className="mt-0.5 text-[11px] text-zinc-500">
            {peer.connected ? 'Direct TCP session · end-to-end encrypted' : 'Session closed'}
          </p>
        </div>
        <LockIcon className={`h-5 w-5 ${peer.connected ? 'text-cyan' : 'text-zinc-700'}`} />
      </header>

      <ol className="min-h-0 flex-1 space-y-3 overflow-y-auto px-5 py-4" data-testid="messages">
        {peer.messages.length === 0 && (
          <li className="pt-10 text-center text-[13px] text-zinc-600">Session established. Say hello.</li>
        )}
        {peer.messages.map((m) => (
          <Message key={m.id} message={m} />
        ))}
        <li ref={bottom} aria-hidden="true" />
      </ol>

      <form onSubmit={submit} className="border-t border-white/[0.06] p-3">
        {error && (
          <p className="mb-2 px-2 text-[12px] text-crimson" role="alert">
            {error}
          </p>
        )}
        <div className="flex items-center gap-2">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={!ready}
            maxLength={2000}
            placeholder={ready ? 'Write a message' : 'Session is not active'}
            autoComplete="off"
            aria-label="Message"
            data-testid="message-input"
            className="min-w-0 flex-1 rounded-xl border border-white/[0.08] bg-black/40 px-4 py-2.5 text-[14px] text-zinc-100 placeholder:text-zinc-600 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={!ready || !draft.trim()}
            data-testid="send-button"
            className="rounded-xl bg-cyan px-5 py-2.5 text-[13px] font-semibold text-black transition hover:bg-cyan/90 disabled:cursor-not-allowed disabled:bg-white/[0.06] disabled:text-zinc-600"
          >
            Send
          </button>
        </div>
      </form>
    </section>
  );
}
