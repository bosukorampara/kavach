import React from "react";

export function GraphCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      borderRadius: 16,
      padding: 12,
      border: "1px solid var(--border)",
      background: "var(--bgElev)",
      minHeight: 320,
      display: "flex",
      flexDirection: "column"
    }}>
      <div style={{ fontSize: 14, opacity: 0.8, marginBottom: 8 }}>{title}</div>
      <div style={{ flex: 1, minHeight: 260 }}>{children}</div>
    </div>
  );
}

