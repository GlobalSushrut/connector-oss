import type { ReactNode } from 'react';

type Props = {
  sid: string;
  children: ReactNode;
  contentClassName?: string;
};

export default function SlideShell({ sid, children, contentClassName = 'slide-content pdf-safe' }: Props) {
  const g1 = `${sid}-rad`;
  const grid = `${sid}-grid`;
  return (
    <div className="slide">
      <svg className="slide-bg" viewBox="0 0 1280 720" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id={g1} cx="24%" cy="34%" r="58%">
            <stop offset="0%" stopColor="#0d2238" />
            <stop offset="100%" stopColor="#06111e" />
          </radialGradient>
          <pattern id={grid} width="64" height="64" patternUnits="userSpaceOnUse">
            <path d="M64 0L0 0 0 64" fill="none" stroke="#11263c" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width="1280" height="720" fill={`url(#${g1})`} />
        <rect width="1280" height="720" fill={`url(#${grid})`} opacity="0.42" />
      </svg>
      <div className={contentClassName}>{children}</div>
    </div>
  );
}
