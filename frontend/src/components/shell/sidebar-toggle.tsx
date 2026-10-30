"use client";

import { useEffect, useState } from "react";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";

export function SidebarToggle() {
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => {
    const saved = window.localStorage.getItem("sentinel-sidebar-collapsed") === "true";
    document.documentElement.dataset.sidebar = saved ? "collapsed" : "expanded";
    const frame = window.requestAnimationFrame(() => setCollapsed(saved));
    return () => window.cancelAnimationFrame(frame);
  }, []);
  function toggle() {
    const next = !collapsed;
    setCollapsed(next);
    document.documentElement.dataset.sidebar = next ? "collapsed" : "expanded";
    window.localStorage.setItem("sentinel-sidebar-collapsed", String(next));
  }
  const Icon = collapsed ? PanelLeftOpen : PanelLeftClose;
  return <button type="button" onClick={toggle} className="sidebar-toggle grid size-9 shrink-0 place-items-center rounded-xl border border-border bg-white/80 text-[var(--text-secondary)] shadow-sm backdrop-blur transition hover:-translate-y-0.5 hover:border-[var(--accent)] hover:text-[var(--accent)]" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!collapsed}><Icon className="size-4" /></button>;
}
