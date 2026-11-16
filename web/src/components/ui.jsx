import React from 'react';

const TONES = {
  cyan: 'border-cyan/30 bg-cyan/[0.08] text-cyan',
  amethyst: 'border-amethyst/30 bg-amethyst/[0.08] text-amethyst',
  crimson: 'border-crimson/40 bg-crimson/[0.1] text-crimson',
  neutral: 'border-white/10 bg-white/[0.04] text-zinc-400',
};

export function Pill({ tone = 'neutral', children, ...rest }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${TONES[tone]}`}
      {...rest}
    >
      {children}
    </span>
  );
}

export function Dot({ tone = 'cyan', pulse = false }) {
  const color = { cyan: 'bg-cyan', amethyst: 'bg-amethyst', crimson: 'bg-crimson', neutral: 'bg-zinc-600' }[tone];
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${color} ${pulse ? 'animate-pulse' : ''}`} />;
}

export function LockIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className} aria-hidden="true">
      <rect x="5" y="10.500" width="14" height="9.500" rx="2.500" />
      <path d="M8.500 10.500V7.500a3.500 3.500 0 017 0v3" strokeLinecap="round" />
      <path d="M12 14.200v2.200" strokeLinecap="round" />
    </svg>
  );
}

export const short = (hex, n = 8) => (hex ? `${hex.slice(0, n)}…${hex.slice(-4)}` : '—');

export const group = (hex, size = 4) => (hex ? hex.match(new RegExp(`.{1,${size}}`, 'g')).join(' ') : '—');
