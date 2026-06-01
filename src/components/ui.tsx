import type { ReactNode } from "react";
import type { Severity } from "../engine/types";
import { cn } from "../utils/cn";

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-white/10 bg-slate-900/40 p-5", className)}>
      {children}
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  className,
  disabled,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  className?: string;
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  const variants = {
    primary:
      "bg-gradient-to-r from-cyan-400 to-indigo-500 text-slate-950 hover:brightness-110 shadow-lg shadow-indigo-500/20",
    ghost: "border border-white/15 bg-white/5 text-white hover:bg-white/10",
    danger: "border border-rose-400/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "rounded-xl px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-40",
        variants[variant],
        className
      )}
    >
      {children}
    </button>
  );
}

export const severityStyle: Record<Severity, string> = {
  critical: "text-rose-300 bg-rose-500/15 border-rose-400/30",
  high: "text-orange-300 bg-orange-500/15 border-orange-400/30",
  medium: "text-amber-300 bg-amber-500/15 border-amber-400/30",
  low: "text-sky-300 bg-sky-500/15 border-sky-400/30",
  info: "text-slate-300 bg-white/5 border-white/15",
};

export function Badge({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium",
        className
      )}
    >
      {children}
    </span>
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-400">
        {label}
      </span>
      {children}
      {hint && <span className="mt-1 block text-[11px] text-slate-500">{hint}</span>}
    </label>
  );
}

export const inputCls =
  "w-full rounded-xl border border-white/10 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/30 placeholder:text-slate-600";
