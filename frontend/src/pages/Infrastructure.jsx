import { useEffect } from "react";
import Icon from "../components/Icon";

const defaultNodes = [
  { ip: "185.23.45.10", host: "mail-relay.pro", city: "Agra", country: "IN", org: "AS12345 BulkHosting", lat: 27.18, lng: 78.01, type: "RELAY", risk: "red" },
  { ip: "41.58.120.77", host: "proxy-ng.net", city: "Lagos", country: "NG", org: "AS37148 MainOne", lat: 6.52, lng: 3.38, type: "PROXY", risk: "red" },
  { ip: "95.216.44.22", host: "vps-de.hetzner.com", city: "Frankfurt", country: "DE", org: "AS24940 Hetzner", lat: 50.11, lng: 8.68, type: "VPS", risk: "orange" },
  { ip: "203.0.113.10", host: "mail.example.com", city: "Mumbai", country: "IN", org: "AS55836 Reliance", lat: 19.07, lng: 72.87, type: "LEGIT", risk: "green" },
  { ip: "198.51.100.25", host: "suspicious-host.test", city: "Amsterdam", country: "NL", org: "AS20473 Vultr", lat: 52.37, lng: 4.89, type: "PHISH", risk: "red" },
];

export default function Infrastructure({ nodes }) {
  const infraNodes = nodes || defaultNodes;

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
      <div id="infra-map" style={{ height: 380, borderRadius: 8, border: "1px solid var(--line)", marginBottom: 24 }} />
      <div className="ti-section-label">IDENTIFIED NODES</div>
      <div className="queue-table">
        <div className="queue-head" style={{ gridTemplateColumns: "100px 1fr 1fr 1fr 80px" }}>
          <span>TYPE</span><span>HOST / IP</span><span>LOCATION</span><span>ASN / ORG</span><span>RISK</span>
        </div>
        {infraNodes.map(n => (
          <div key={n.ip} className="queue-row" style={{ gridTemplateColumns: "100px 1fr 1fr 1fr 80px" }}>
            <span><span className="ioc-type-badge">{n.type}</span></span>
            <span style={{ fontFamily: "'Space Mono',monospace", fontSize: 9 }}>{n.host}<br /><span style={{ color: "var(--muted)" }}>{n.ip}</span></span>
            <span style={{ fontSize: 10 }}>{n.city}, {n.country}</span>
            <span style={{ fontSize: 10, color: "var(--muted)" }}>{n.org}</span>
            <span className={`severity ${n.risk}`}>{(n.risk || "medium").toUpperCase()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
