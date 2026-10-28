import React, { useEffect, useState } from "react";
import { Line, Bar, Doughnut } from "react-chartjs-2";
import { Chart, CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend } from "chart.js";
import { GraphCard } from "./GraphCard";
import { useJson } from "../hooks/useJson";
import { uniqStrings } from "../utils/uniq";
import { useTheme } from "../theme/Theme";

Chart.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend);

function cssColor(prop: string, fallback: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(prop).trim() || fallback;
}

function useAxisColors() {
  const { theme } = useTheme();
  const [colors, setColors] = useState({
    fg: cssColor("--fg", "#111"),
    grid: cssColor("--border", "#e5e7eb")
  });

  useEffect(() => {
    // Update colors when theme changes
    const updateColors = () => {
      setColors({
        fg: cssColor("--fg", theme === "dark" ? "#e5e7eb" : "#111"),
        grid: cssColor("--border", theme === "dark" ? "#27303a" : "#e5e7eb")
      });
    };
    
    updateColors();
    // Also listen for CSS variable changes
    const interval = setInterval(updateColors, 100);
    return () => clearInterval(interval);
  }, [theme]);

  return colors;
}

export function ThreatTrendsCard() {
  const { data } = useJson<any[]>("/api/dashboard/threat-trends?window=7d", 30000);
  const c = useAxisColors();
  
  if (!data || data.length === 0) {
    return <GraphCard title="Threat Trends (7d)">No data yet.</GraphCard>;
  }
  
  const days = uniqStrings(data.map(d => String(d.day))).sort();
  const types = uniqStrings(data.map(d => String(d.threat_type)));
  
  const datasets = types.map((t, idx) => ({
    label: t,
    data: days.map(day => {
      const entry = data.find(r => String(r.day) === day && String(r.threat_type) === t);
      return entry ? entry.count : 0;
    }),
    fill: true,
    borderColor: `hsl(${idx * 60}, 70%, 50%)`,
    backgroundColor: `hsla(${idx * 60}, 70%, 50%, 0.1)`,
    tension: 0.4
  }));
  
  return (
    <GraphCard title="Threat Trends (7d)">
      <Line
        data={{ labels: days, datasets }}
        options={{
          maintainAspectRatio: false,
          responsive: true,
          plugins: {
            legend: { position: "bottom", labels: { color: c.fg } }
          },
          scales: {
            x: { grid: { color: c.grid }, ticks: { color: c.fg } },
            y: { grid: { color: c.grid }, ticks: { color: c.fg }, beginAtZero: true }
          }
        }}
      />
    </GraphCard>
  );
}

export function TopAttackTypesCard() {
  const { data } = useJson<any[]>("/api/dashboard/top-attack-types?limit=10&window=7d", 30000);
  const c = useAxisColors();
  
  if (!data || data.length === 0) {
    return <GraphCard title="Top Attack Types">No data yet.</GraphCard>;
  }
  
  return (
    <GraphCard title="Top Attack Types">
      <Bar
        data={{
          labels: data.map(d => d.threat_type),
          datasets: [{
            label: "Count",
            data: data.map(d => d.count),
            backgroundColor: "rgba(220, 53, 69, 0.8)",
            borderColor: "rgb(220, 53, 69)",
            borderWidth: 1
          }]
        }}
        options={{
          maintainAspectRatio: false,
          indexAxis: "y",
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: { grid: { color: c.grid }, ticks: { color: c.fg }, beginAtZero: true },
            y: { grid: { color: c.grid }, ticks: { color: c.fg } }
          }
        }}
      />
    </GraphCard>
  );
}

export function SeverityDonutCard() {
  const { data } = useJson<any[]>("/api/dashboard/severity-dist?window=7d", 30000);
  const c = useAxisColors();
  
  if (!data || data.length === 0) {
    return <GraphCard title="Severity Distribution">No data yet.</GraphCard>;
  }
  
  const colors = {
    CRITICAL: 'rgba(220, 53, 69, 0.8)',
    HIGH: 'rgba(255, 193, 7, 0.8)',
    MEDIUM: 'rgba(40, 167, 69, 0.8)',
    LOW: 'rgba(23, 162, 184, 0.8)'
  };
  
  return (
    <GraphCard title="Severity Distribution">
      <Doughnut
        data={{
          labels: data.map(d => d.severity),
          datasets: [{
            data: data.map(d => d.count),
            backgroundColor: data.map(d => colors[d.severity as keyof typeof colors] || 'rgba(128, 128, 128, 0.8)')
          }]
        }}
        options={{
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { color: c.fg } }
          }
        }}
      />
    </GraphCard>
  );
}

export function TopSourceIPsCard() {
  const { data } = useJson<any[]>("/api/dashboard/top-source-ips?limit=20&window=7d", 30000);
  const c = useAxisColors();
  
  if (!data || data.length === 0) {
    return <GraphCard title="Top Source IPs">No data yet.</GraphCard>;
  }
  
  return (
    <GraphCard title="Top Source IPs">
      <Bar
        data={{
          labels: data.slice(0, 15).map(d => d.source_ip),
          datasets: [{
            label: "Events",
            data: data.slice(0, 15).map(d => d.events),
            backgroundColor: "rgba(255, 193, 7, 0.8)",
            borderColor: "rgb(255, 193, 7)",
            borderWidth: 1
          }]
        }}
        options={{
          maintainAspectRatio: false,
          indexAxis: "y",
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: { grid: { color: c.grid }, ticks: { color: c.fg }, beginAtZero: true },
            y: { grid: { color: c.grid }, ticks: { color: c.fg } }
          }
        }}
      />
    </GraphCard>
  );
}

export function HoneytokenHourHeatmapCard() {
  const { data } = useJson<any[]>("/api/dashboard/honeytoken-heatmap?window=7d", 30000);
  const c = useAxisColors();
  
  if (!data || data.length === 0) {
    return <GraphCard title="Honeytoken Hits by Hour">No data yet.</GraphCard>;
  }
  
  const targets = uniqStrings(data.map(d => String(d.target)));
  const hours = Array.from({ length: 24 }, (_, i) => i);
  
  const datasets = targets.map((t, idx) => ({
    label: t,
    data: hours.map(h => {
      const entry = data.find(d => String(d.target) === t && Number(d.hour) === h);
      return entry ? entry.count : 0;
    }),
    backgroundColor: `hsla(${idx * 40}, 70%, 50%, 0.6)`,
    borderColor: `hsl(${idx * 40}, 70%, 50%)`,
    borderWidth: 1
  }));
  
  return (
    <GraphCard title="Honeytoken Hits by Hour">
      <Bar
        data={{ labels: hours.map(String), datasets }}
        options={{
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { color: c.fg } }
          },
          scales: {
            x: { grid: { color: c.grid }, ticks: { color: c.fg }, stacked: true },
            y: { grid: { color: c.grid }, ticks: { color: c.fg }, stacked: true, beginAtZero: true }
          }
        }}
      />
    </GraphCard>
  );
}

