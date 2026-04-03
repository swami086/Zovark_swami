/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        zovark: {
          bg: "#09090b",
          card: "#18181b",
          border: "#27272a",
          hover: "#3f3f46",
          accent: "#10b981",
          "accent-dim": "#059669",
          text: "#f4f4f5",
          muted: "#a1a1aa",
        },
      },
    },
  },
  plugins: [],
};
