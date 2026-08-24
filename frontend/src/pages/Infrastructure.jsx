import { useEffect } from "react";
import Icon from "../components/Icon";
import { dash } from "../App";

export default function Infrastructure({ nodes }) {
  const infraNodes = nodes || [];

  useEffect(() => {
    const L = window.L;
    if (!L) return;

    const mapElement = document.getElementById("infra-map");
    if (!mapElement) return;

    // Re-initialize map if container exists
    if (mapElement._leaflet_id) {
      mapElement._leaflet_id = null;
      mapElement.innerHTML = "";
    }

    const map = L.map("infra-map").setView([20, 10], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "© OpenStreetMap contributors",
    }).addTo(map);

    const colors = { red: "#e96856", orange: "#e1a142", green: "#56a987" };
    infraNodes.forEach(node => {
      if (node.lat && node.lng) {
        const circle = L.circleMarker([node.lat, node.lng], {
          radius: 8,
          fillColor: colors[node.risk] || "#648fa5",
          color: "#fff",
          weight: 2,
          opacity: 1,
          fillOpacity: 0.85,
        }).addTo(map);
        circle.bindPopup(`<b>${node.host || node.ip}</b><br/>${node.ip}<br/>${node.city || "Unknown"}, ${node.country || ""}<br/><small>${node.org || ""}</small>`);
      }
    });

    return () => {
      map.remove();
    };
  }, [infraNodes]);

  return (
    <div>
      <section className="welcome" style={{ marginBottom: 28 }}>
        <div>
          <p className="eyebrow">INFRASTRUCTURE</p>
          <h1>Sender infrastructure map</h1>
          <p className="lede">Geolocation of all identified sending nodes and relay servers.</p>
        </div>
      </section>
      <div id="infra-map" style={{ height: 380, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 24, display: infraNodes.length === 0 ? "none" : undefined }} />
      {infraNodes.length === 0 && (
        <p style={{ padding: "20px", color: "var(--muted)", fontSize: 13, border: "1px dashed var(--line)", borderRadius: 8 }}>
          No infrastructure observed yet — sender IPs appear here automatically as emails are analyzed.
        </p>
      )}
      <div className="ti-section-label">IDENTIFIED NODES</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "100px 1fr 1fr 1fr 80px" }}>
          <span>TYPE</span><span>HOST / IP</span><span>LOCATION</span><span>ASN / ORG</span><span>RISK</span>
        </div>
        {infraNodes.length === 0 && (
          <p style={{ padding: "20px", color: "var(--muted)", fontSize: 13 }}>No nodes recorded.</p>
        )}
        {infraNodes.map(n => (
          <div key={n.ip} className="queue-row" style={{ gridTemplateColumns: "100px 1fr 1fr 1fr 80px" }}>
            <span><span className="ioc-type-badge">{n.type}</span></span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 10 }}>{dash(n.host)}<br /><span style={{ color: "var(--muted)" }}>{n.ip}</span></span>
            <span style={{ fontSize: 11 }}>{n.city || "—"}{n.country ? `, ${n.country}` : ""}</span>
            <span style={{ fontSize: 11, color: "var(--muted)" }}>{dash(n.org)}</span>
            <span className={`severity ${n.risk}`}>{(n.risk || "medium").toUpperCase()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
