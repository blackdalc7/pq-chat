import React from 'react';
import { api } from '../api.js';
import { Dot, Pill } from './ui.jsx';

function Row({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <dt className="text-[12px] text-zinc-500">{label}</dt>
      <dd className="text-right font-mono text-[12px] text-zinc-200">{children}</dd>
    </div>
  );
}

function Algorithm({ name, detail, active }) {
  return (
    <li className="flex items-center justify-between gap-3 py-1.5" data-testid="algorithm" data-active={active}>
      <span>
        <span className="block font-mono text-[12px] text-zinc-100">{name}</span>
        <span className="block text-[11px] text-zinc-500">{detail}</span>
      </span>
      <span className={`flex items-center gap-1.5 text-[11px] ${active ? 'text-amethyst' : 'text-zinc-600'}`}>
        <Dot tone={active ? 'amethyst' : 'neutral'} />
        {active ? 'active' : 'idle'}
      </span>
    </li>
  );
}

function SafetyNumber({ peer }) {
  return (
    <section className="border-t border-white/[0.06] pt-4">
      <div className="flex items-center justify-between">
        <h3 className="label">Safety number</h3>
        {peer.verified ? (
          <Pill tone="cyan" data-testid="verified-badge">
            Verified
          </Pill>
        ) : (
          <button
            type="button"
            onClick={() => api.verify(peer.id).catch(() => {})}
            data-testid="verify-button"
            className="rounded-full border border-white/10 px-2.5 py-0.5 text-[11px] text-zinc-300 transition hover:border-cyan/40 hover:text-cyan"
          >
            Mark as verified
          </button>
        )}
      </div>
      <p className="mt-3 grid grid-cols-4 gap-x-3 gap-y-1.5 font-mono text-[12.5px] tracking-wider text-zinc-200" data-testid="safety-number">
        {peer.safety_number.split(' ').map((part, i) => (
          // eslint-disable-next-line react/no-array-index-key
          <span key={i}>{part}</span>
        ))}
      </p>
      <p className="mt-3 text-[11px] leading-relaxed text-zinc-600">
        Compare with your contact in person or on a call. Matching numbers mean nobody is sitting in the middle.
      </p>
    </section>
  );
}

const KIND_TONE = { ratchet: 'text-amethyst', error: 'text-crimson', verify: 'text-cyan', handshake: 'text-cyan' };

export default function CryptoPanel({ state, peer }) {
  const active = Boolean(peer?.connected);
  const r = peer?.ratchet;

  return (
    <aside className="glass flex min-h-0 flex-col gap-4 overflow-y-auto p-5" data-testid="crypto-panel">
      <div className="flex items-center justify-between">
        <h2 className="label">Cryptographic state</h2>
        <Pill tone={active ? 'amethyst' : 'neutral'} data-testid="hybrid-status">
          {active ? 'Hybrid PQ active' : 'No session'}
        </Pill>
      </div>

      <section>
        <h3 className="label mb-1">Key exchange · X-Wing</h3>
        <ul className="divide-y divide-white/[0.04]">
          <Algorithm name="X25519" detail="Classical elliptic-curve Diffie-Hellman" active={active} />
          <Algorithm name="ML-KEM-768" detail="Post-quantum lattice KEM · FIPS 203" active={active} />
        </ul>
        <h3 className="label mb-1 mt-4">Authentication</h3>
        <ul className="divide-y divide-white/[0.04]">
          <Algorithm name="Ed25519" detail="Classical signature" active={active} />
          <Algorithm name="ML-DSA-65" detail="Post-quantum signature · FIPS 204" active={active} />
        </ul>
        <dl className="mt-3 border-t border-white/[0.06] pt-2">
          <Row label="Cipher">{state.algorithms.aead}</Row>
          <Row label="Key derivation">{state.algorithms.kdf}</Row>
        </dl>
      </section>

      {peer && (
        <>
          <section className="border-t border-white/[0.06] pt-4">
            <h3 className="label">Session key hash</h3>
            {/* A one-way tag of the current sending chain key, never the key itself. */}
            <p className="mt-2 font-mono text-[19px] tracking-wide text-amethyst" data-testid="session-key-hash">
              {r.send_chain_tag ? r.send_chain_tag.match(/.{4}/g).join(' ') : 'waiting for peer'}
            </p>
            <p className="mt-1 text-[11px] text-zinc-600">Changes with every message you send.</p>
            <dl className="mt-3">
              <Row label="Root key hash">
                <span data-testid="root-key-hash">{r.root_tag}</span>
              </Row>
              <Row label="Ratchet epoch">
                <span data-testid="ratchet-epoch">{r.epoch}</span>
              </Row>
              <Row label="Sent in this epoch">{r.send_n}</Row>
              <Row label="Received in this epoch">{r.recv_n}</Row>
              <Row label="Current ratchet key">{r.ratchet_pk_tag}</Row>
              <Row label="Peer authenticated by">
                <span className="font-sans">{peer.authenticated_by}</span>
              </Row>
            </dl>
          </section>

          <SafetyNumber peer={peer} />

          <section className="border-t border-white/[0.06] pt-4">
            <h3 className="label mb-2">Protocol log</h3>
            <ol className="space-y-1.5" data-testid="protocol-log">
              {[...peer.events].reverse().map((event, i) => (
                // eslint-disable-next-line react/no-array-index-key
                <li key={i} className="text-[11px] leading-relaxed text-zinc-500">
                  <span className={`mr-2 font-mono uppercase ${KIND_TONE[event.kind] || 'text-zinc-500'}`}>{event.kind}</span>
                  {event.detail}
                </li>
              ))}
            </ol>
          </section>
        </>
      )}
    </aside>
  );
}
