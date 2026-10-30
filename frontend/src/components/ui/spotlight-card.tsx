"use client";

import type { CSSProperties, PointerEvent, ReactNode } from "react";
import { cn } from "@/lib/utils";

type GlowColor = "blue" | "purple" | "green" | "orange";
const hue:Record<GlowColor,string>={blue:"258 72% 70%",purple:"268 68% 70%",green:"174 60% 48%",orange:"24 82% 62%"};

export function SpotlightCard({children,className,glowColor="blue"}:{children:ReactNode;className?:string;glowColor?:GlowColor}){
  const move=(event:PointerEvent<HTMLElement>)=>{
    const rect=event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty("--spot-x",`${event.clientX-rect.left}px`);
    event.currentTarget.style.setProperty("--spot-y",`${event.clientY-rect.top}px`);
    event.currentTarget.style.setProperty("--spot-opacity","1");
  };
  const leave=(event:PointerEvent<HTMLElement>)=>event.currentTarget.style.setProperty("--spot-opacity","0");
  return <article onPointerMove={move} onPointerLeave={leave} style={{"--spot-color":hue[glowColor]} as CSSProperties} className={cn("spotlight-card panel",className)}><span className="spotlight-card-glow" aria-hidden="true"/>{children}</article>;
}
