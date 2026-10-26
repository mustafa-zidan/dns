import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    // Keep every script and style in files so the CSP can stay at 'self'.
    assetsInlineLimit: 0,
  },
});
