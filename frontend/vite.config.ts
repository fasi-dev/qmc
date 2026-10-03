import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globalSetup: "./vitest.global.ts",          // starts a real backend for the UI tests
    env: { VITE_API_URL: "http://127.0.0.1:8031" },
    testTimeout: 30000,
    include: ["src/**/*.test.tsx"],
  },
});
