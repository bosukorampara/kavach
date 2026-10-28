import { useEffect, useState } from "react";

export function useJson<T=any[]>(url: string, intervalMs = 30000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    let t: any;
    
    const fetcher = async () => {
      try {
        const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
        const res = await fetch(`${API_BASE_URL}${url}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        const jsonData = await res.json();
        // Handle both array and object responses
        const finalData = Array.isArray(jsonData) ? jsonData : (jsonData.trends || jsonData.distribution || jsonData.top_attacks || jsonData.top_ips || jsonData.heatmap || jsonData);
        setData(finalData as T);
        setError(null);
      } catch (e: any) {
        setError(e?.message || "fetch error");
      }
    };
    
    fetcher();
    t = setInterval(fetcher, intervalMs);
    
    return () => clearInterval(t);
  }, [url, intervalMs]);
  
  return { data, error, loading: data === null && !error };
}

