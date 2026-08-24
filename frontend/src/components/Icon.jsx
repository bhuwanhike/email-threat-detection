export default function Icon({ name, size = 18 }) {
  const icons = {
    grid: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
    inbox: "M4 5h16v14H4zM4 13h4l2 2h4l2-2h4",
    radar: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6-6",
    map: "M3 6l6-3 6 3 6-3v15l-6 3-6-3-6 3zM9 3v15M15 6v15",
    clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
    settings: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19 13.5l2 1-2 3-2-1a7 7 0 0 1-2 1l-.3 2.2h-3.4L11 17.5a7 7 0 0 1-2-1l-2 1-2-3 2-1a7 7 0 0 1 0-3L5 9.5l2-3 2 1a7 7 0 0 1 2-1L11.3 4h3.4L15 6.5a7 7 0 0 1 2 1l2-1 2 3-2 1a7 7 0 0 1 0 3z",
    search: "m20 20-4-4M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z",
    upload: "M12 16V4m0 0L7 9m5-5 5 5M4 20h16",
    chevron: "m9 18 6-6-6-6",
    more: "M5 12h.01M12 12h.01M19 12h.01",
    shield: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z",
    link: "M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1M14 11a5 5 0 0 0-7.1-.1l-2 2a5 5 0 0 0 7.1 7.1l1.1-1.1",
    file: "M6 3h8l4 4v14H6zM14 3v5h5M9 13h6M9 17h4",
    copy: "M8 8V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-3M4 9h9a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z",
    server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
    skull: "M12 4a7 7 0 0 1 7 7c0 2.8-1.6 5.2-4 6.5V20H9v-2.5C6.6 16.2 5 13.8 5 11a7 7 0 0 1 7-7zM9 21h6M10 17v-1M14 17v-1",
    zap: "M13 2 3 14h9l-1 8 10-12h-9l1-8z",
    alert: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01",
    target: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z",
    eye: "M1 12S5 5 12 5s11 7 11 7-4 7-11 7S1 12 1 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
    check: "M20 6 9 17l-5-5",
    x: "M18 6 6 18M6 6l12 12",
    globe: "M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
    hash: "M4 9h16M4 15h16M10 3 8 21M16 3l-2 18",
    lock: "M7 11V8a5 5 0 0 1 10 0v3M6 11h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z",
    logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
    moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
    sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  };
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d={icons[name] || icons.grid} />
    </svg>
  );
}
