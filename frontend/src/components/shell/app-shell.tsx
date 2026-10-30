import { MotionSurface } from "@/components/prism/motion-surface";
import Link from "next/link";
import { Bell, Orbit, Search, ShieldCheck } from "lucide-react";
import type { SystemStatusSnapshot } from "@/domain/sentinel";
import { SystemStatus } from "@/components/system/system-status";
import { SidebarNav } from "./sidebar-nav";
import { WorkspaceContent } from "@/components/incident/incident-views";
import { Component as BackgroundSnippets } from "@/components/ui/background-snippets";
import { SidebarToggle } from "./sidebar-toggle";
import { PageBackButton } from "./page-back-button";

export function AppShell({ children, system }: { children: React.ReactNode; system: SystemStatusSnapshot }) {
  return (
    <MotionSurface><div className="app-shell relative isolate min-h-screen bg-transparent lg:grid lg:grid-cols-[260px_minmax(0,1fr)]">
      <BackgroundSnippets />
      <a href="#main-content" className="fixed left-3 top-3 z-50 -translate-y-20 rounded-lg bg-[var(--accent)] px-3 py-2 text-[12px] font-semibold text-white transition-transform focus:translate-y-0">Skip to main content</a>
      <aside className="app-sidebar hidden border-r border-white/70 bg-white/76 shadow-[12px_0_38px_rgb(16_42_67/0.06)] lg:fixed lg:inset-y-0 lg:flex lg:w-[260px] lg:flex-col lg:backdrop-blur-2xl">
        <Link href="/" className="flex min-h-[92px] items-center gap-3 border-b border-border px-5">
          <span className="relative grid size-11 shrink-0 place-items-center overflow-hidden rounded-[14px] bg-[var(--foreground)] text-white shadow-[0_8px_22px_rgb(16_36_62/0.16)]"><ShieldCheck className="size-5" /><Orbit className="absolute size-9 text-[#a891ff] opacity-65" /></span>
          <span className="sidebar-hide"><span className="flex items-center gap-1.5 text-[17px] font-bold tracking-[-0.035em]">SentinelAI <b className="quantum-text">Q</b></span><span className="mt-1 block max-w-[164px] text-[9px] font-medium leading-3.5 text-[var(--text-muted)]">Hybrid Quantum-Classical Threat Intelligence</span></span>
        </Link>
        <div className="flex-1 py-6"><SidebarNav /></div>
        <div className="sidebar-status m-4 rounded-[16px] border border-white/80 bg-white/55 p-4 shadow-[0_12px_30px_rgb(8_111_131/0.08)] backdrop-blur-xl">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-foreground"><span className="size-2 rounded-full bg-[var(--accent)]" />Source · {system.mode}</div>
          <SystemStatus system={system} />
        </div>
      </aside>

      <div className="min-w-0 lg:col-start-2">
        <header className="sticky top-0 z-30 border-b border-border bg-white/88 backdrop-blur-xl">
          <div className="flex h-[64px] items-center gap-3 px-4 md:px-7">
            <SidebarToggle /><PageBackButton />
            <form action="/threat-investigation" className="relative ml-auto w-full max-w-[360px]">
              <Search aria-hidden="true" className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
              <input name="q" aria-label="Search threats" placeholder="Search alerts or employees" className="control w-full bg-[var(--surface-elevated)] pl-9 pr-3 placeholder:text-[var(--text-muted)]" />
            </form>
            <Link href="/threat-investigation" aria-label="Open threat investigation" className="grid size-9 place-items-center rounded-lg border border-border bg-white text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"><Bell className="size-4" /></Link>
            <div className="hidden border-l border-border pl-4 sm:block"><span className="flex items-center gap-1.5 text-[11px] font-semibold"><span className="size-1.5 rounded-full bg-[var(--accent)]" />Data · {system.data.status}</span><span className="text-[9px] text-[var(--text-muted)]">{system.data.label} · {system.model.status}</span></div>
          </div>
          <div className="border-t border-border lg:hidden"><SidebarNav compact /></div>
        </header>
        <main id="main-content" tabIndex={-1} className="site-content px-4 py-6 md:px-7 md:py-7 xl:px-9 xl:py-8"><WorkspaceContent>{children}</WorkspaceContent></main>
      </div>
    </div></MotionSurface>
  );
}
