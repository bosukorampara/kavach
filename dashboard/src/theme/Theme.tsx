import React, { createContext, useContext, useEffect, useState } from "react";

type Theme = "light" | "dark";

const Ctx = createContext<{theme: Theme; toggle: () => void}>({theme: "light", toggle: () => {}});

export const useTheme = () => useContext(Ctx);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("kavach-theme");
    return (stored === "dark" || stored === "light") ? stored : "light";
  });
  
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
    localStorage.setItem("kavach-theme", theme);
  }, [theme]);
  
  return (
    <Ctx.Provider value={{ theme, toggle: () => setTheme(t => t === "dark" ? "light" : "dark") }}>
      {children}
    </Ctx.Provider>
  );
}

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  
  return (
    <button
      onClick={toggle}
      style={{
        borderRadius: 10,
        padding: "6px 10px",
        border: "1px solid var(--border)",
        background: "var(--bgElev)",
        color: "var(--fg)",
        cursor: "pointer"
      }}
    >
      {theme === "dark" ? "☀️ Light" : "🌙 Dark"}
    </button>
  );
}

