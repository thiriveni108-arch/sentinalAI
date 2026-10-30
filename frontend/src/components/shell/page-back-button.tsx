"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";

export function PageBackButton() {
  const router = useRouter();
  function goBack() {
    if (window.history.length > 1) router.back();
    else router.push("/");
  }
  return <button type="button" onClick={goBack} className="page-back-button inline-flex h-9 items-center gap-2 rounded-xl border border-border bg-white/75 px-3 text-[10px] font-semibold text-[var(--text-secondary)] shadow-sm backdrop-blur transition hover:-translate-x-0.5 hover:border-[var(--accent)] hover:text-[var(--accent)]"><ArrowLeft className="size-3.5" /><span className="hidden sm:inline">Back</span></button>;
}
