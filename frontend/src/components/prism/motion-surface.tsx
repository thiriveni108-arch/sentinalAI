"use client";

import { useRef, type PointerEvent, type ReactNode } from "react";

/** Delegated pointer effects: CSS variables only, no React renders on pointer movement. */
export function MotionSurface({ children }: { children: ReactNode }) {
  const active = useRef<HTMLElement | null>(null);
  function reset() {
    active.current?.style.removeProperty("transform");
    active.current?.style.removeProperty("--spot-opacity");
    active.current = null;
  }
  function move(event: PointerEvent<HTMLDivElement>) {
    if (event.pointerType !== "mouse" || window.matchMedia("(prefers-reduced-motion: reduce), (max-width: 900px)").matches) return;
    const target = (event.target as HTMLElement).closest<HTMLElement>(".tilt-card, .magnetic, .prism-hero, .panel:not(.spotlight-card)");
    if (active.current !== target) reset();
    if (!target) return;
    active.current = target;
    const rect = target.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - .5;
    const y = (event.clientY - rect.top) / rect.height - .5;
    target.style.setProperty("--pointer-x", `${(x + .5) * 100}%`);
    target.style.setProperty("--pointer-y", `${(y + .5) * 100}%`);
    target.style.setProperty("--spot-opacity", "1");
    if (target.classList.contains("magnetic")) target.style.transform = `translate(${x * 5}px, ${y * 5}px)`;
    else if (target.classList.contains("tilt-card")) target.style.transform = `perspective(900px) translateY(-6px) rotateX(${-y * 6}deg) rotateY(${x * 6}deg)`;
  }
  return <div onPointerMove={move} onPointerLeave={reset} onPointerCancel={reset}>{children}</div>;
}
