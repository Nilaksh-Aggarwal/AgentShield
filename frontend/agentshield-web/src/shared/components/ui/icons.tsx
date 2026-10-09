import type { ReactNode } from 'react'

export interface IconProps {
  className?: string
}

/** Decorative only: every icon sits next to text that carries the same meaning, so it is hidden from assistive tech. */
function Icon({ className = 'size-4', children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  )
}

export function ShieldIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3 5 5.8v5.6c0 4.6 3 8.4 7 9.6 4-1.2 7-5 7-9.6V5.8L12 3Z" />
      <path d="m9 12 2 2 4-4" />
    </Icon>
  )
}

export function OverviewIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </Icon>
  )
}

export function AnalyzeIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m20.5 20.5-4.9-4.9" />
    </Icon>
  )
}

export function ActivityIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />
    </Icon>
  )
}

export function ArrowRightIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 12h14" />
      <path d="m13 6 6 6-6 6" />
    </Icon>
  )
}

export function InfoIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5" />
      <path d="M12 8h.01" />
    </Icon>
  )
}

export function CheckCircleIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="m8.5 12.5 2.5 2.5 4.5-5" />
    </Icon>
  )
}

export function WarningIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M10.3 4.1 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 4.1a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9.5v4" />
      <path d="M12 17h.01" />
    </Icon>
  )
}

export function BlockIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="m5.7 5.7 12.6 12.6" />
    </Icon>
  )
}

export function ErrorIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5" />
      <path d="M12 16h.01" />
    </Icon>
  )
}

export function InboxIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 13.5h4l1.5 2.5h5l1.5-2.5h4" />
      <path d="M5.5 5.5h13L20 13.5V19a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 19v-5.5l1.5-8Z" />
    </Icon>
  )
}

export function TextIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 6.5V5h14v1.5" />
      <path d="M12 5v14" />
      <path d="M9 19h6" />
    </Icon>
  )
}

export function RulesIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 6.5h11" />
      <path d="M9 12h11" />
      <path d="M9 17.5h11" />
      <path d="m3.5 6.5 1.2 1.2 2-2.2" />
      <path d="m3.5 12 1.2 1.2 2-2.2" />
      <path d="m3.5 17.5 1.2 1.2 2-2.2" />
    </Icon>
  )
}

export function EyeOffIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M10.6 5.6A9.7 9.7 0 0 1 12 5.5c5 0 8.5 4.5 9.5 6.5a13 13 0 0 1-2.6 3.4" />
      <path d="M6.6 6.6C4.5 8 3.1 10 2.5 12c1 2 4.5 6.5 9.5 6.5a9.6 9.6 0 0 0 5.4-1.6" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="m3 3 18 18" />
    </Icon>
  )
}

export function ChipIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="6.5" y="6.5" width="11" height="11" rx="2" />
      <path d="M10 10h4v4h-4z" />
      <path d="M9.5 3v3.5M14.5 3v3.5M9.5 17.5V21M14.5 17.5V21M3 9.5h3.5M3 14.5h3.5M17.5 9.5H21M17.5 14.5H21" />
    </Icon>
  )
}

export function LayersIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="m12 3.5 8.5 4.5-8.5 4.5L3.5 8 12 3.5Z" />
      <path d="m3.5 12 8.5 4.5 8.5-4.5" />
      <path d="m3.5 16 8.5 4.5 8.5-4.5" />
    </Icon>
  )
}

export function GaugeIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 16a8 8 0 1 1 16 0" />
      <path d="m12 16 4-5" />
      <path d="M4 16h2M18 16h2" />
    </Icon>
  )
}

export function ScaleIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4v16" />
      <path d="M8 20h8" />
      <path d="M5 7h14" />
      <path d="m5 7-2.5 6a2.5 2.5 0 0 0 5 0L5 7Z" />
      <path d="m19 7-2.5 6a2.5 2.5 0 0 0 5 0L19 7Z" />
    </Icon>
  )
}

export function FlagIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 21V4" />
      <path d="M5 4.5h11l-2 4 2 4H5" />
    </Icon>
  )
}

export function LockIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="5" y="10.5" width="14" height="10" rx="2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
    </Icon>
  )
}

export function XIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="m6 6 12 12" />
      <path d="M18 6 6 18" />
    </Icon>
  )
}

export function ChevronDownIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="m6 9 6 6 6-6" />
    </Icon>
  )
}

export function CircleIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="8" />
    </Icon>
  )
}

export function KeyIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.8 12.2 8.7-8.7" />
      <path d="m16.5 6.5 2.5 2.5" />
      <path d="m14 9 2 2" />
    </Icon>
  )
}

export function UserIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="8" r="4" />
      <path d="M4.5 20.5a7.5 7.5 0 0 1 15 0" />
    </Icon>
  )
}

export function CodeIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="m8 7-5 5 5 5" />
      <path d="m16 7 5 5-5 5" />
      <path d="m13.5 4.5-3 15" />
    </Icon>
  )
}

export function CircuitOffIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 12h5" />
      <path d="M16 12h5" />
      <circle cx="8" cy="12" r="1.5" />
      <circle cx="16" cy="12" r="1.5" />
      <path d="m9.3 11.3 5.2-4.3" />
    </Icon>
  )
}

export function ClipboardCheckIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="5" y="4.5" width="14" height="16" rx="2" />
      <path d="M9 4.5V3.5h6v1" />
      <path d="m9 13 2 2 4-4" />
    </Icon>
  )
}

export function ArrowDownIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 5v14" />
      <path d="m6 13 6 6 6-6" />
    </Icon>
  )
}

export function SpinnerIcon({ className = 'size-4' }: IconProps) {
  return (
    <Icon className={`animate-spin motion-reduce:animate-none ${className}`}>
      <circle cx="12" cy="12" r="9" className="opacity-25" />
      <path d="M21 12a9 9 0 0 0-9-9" />
    </Icon>
  )
}
