"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Bell, Atom, BrainCircuit, FlaskConical, LayoutDashboard, ShieldAlert, UserRoundSearch, Share2, Crosshair, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { plannedModules, type PlannedModuleSlug } from "@/config/navigation";
import { cn } from "@/lib/utils";

const primary = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/threats", label: "Threats", icon: ShieldAlert },
  { href: "/graph", label: "Graph Analysis", icon: Share2 },
  { href: "/threat-intelligence", label: "Threat Intelligence", icon: Crosshair },
  { href: "/quantum", label: "Quantum Analysis", icon: Atom },
  { href: "/shield", label: "SHIELD Decision Lab", icon: ShieldCheck },
  { href: "/attack-lab", label: "Attack Lab", icon: FlaskConical },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/users", label: "User Behaviour", icon: UserRoundSearch },
  { href: "/models", label: "Detection Models", icon: BrainCircuit },
];
const plannedIcons: Record<PlannedModuleSlug, LucideIcon> = {
};

export function SidebarNav({ compact = false }: { compact?: boolean }) {
  const pathname = usePathname();
  return (
    <nav aria-label={compact ? "Mobile navigation" : "Primary navigation"} className={compact ? "flex h-12 items-stretch overflow-x-auto px-3" : "space-y-1.5 px-3"}>
      {!compact && <div className="px-3 pb-2 tech-label">Workspace</div>}
      {primary.map(({ href, label, icon: Icon }) => {
        const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
        return (
          <Link key={href} href={href} aria-current={active ? "page" : undefined} className={cn(
            "flex items-center gap-3 border-transparent text-[12px] font-medium transition-all hover:translate-x-0.5 focus-visible:z-10",
            compact ? "border-b-2 px-3" : "h-10 rounded-lg border-l-2 px-3",
            active ? (href === "/quantum" ? "border-[var(--quantum)] bg-[var(--quantum-soft)] font-semibold text-[var(--quantum-strong)]" : "border-[var(--accent)] bg-[var(--surface-selected)] font-semibold text-foreground") : (href === "/quantum" ? "text-[var(--quantum-strong)] hover:bg-[var(--quantum-soft)]" : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] hover:text-foreground"),
          )}>
            <Icon aria-hidden="true" className={cn("size-4", active && (href === "/quantum" ? "text-[var(--quantum)]" : "text-[var(--accent)]"))} />
            <span>{label}</span>
          </Link>
        );
      })}
      {!compact && plannedModules.length > 0 && <div className="px-3 pt-4 pb-1 tech-label">Planned modules</div>}
      {plannedModules.map(({ slug, label }, index) => {
        const href = `/planned/${slug}`;
        const active = pathname === href;
        const Icon = plannedIcons[slug];

        return (
          <Link
            key={slug}
            href={href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2 border-transparent text-[12px] transition-all hover:translate-x-0.5 focus-visible:z-10",
              compact ? "border-b-2 px-3" : "h-9 border-l-2 px-3",
              compact && index === 0 && "ml-2 border-l border-l-border",
              active
                ? "border-[var(--text-muted)] bg-[var(--surface-selected)] text-[var(--text-secondary)]"
                : "text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-secondary)]",
            )}
          >
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            <span className="whitespace-nowrap">{label}</span>
            <span className="ml-auto whitespace-nowrap rounded-sm border border-[var(--border-strong)] px-1.5 py-0.5 font-mono text-[8px] font-semibold tracking-[0.08em] text-[var(--text-muted)]">
              Planned
            </span>
          </Link>
        );
      })}
    </nav>
  );
}
