import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

/**
 * Vitest configuration.
 *
 * The suite covers pure logic (URL validation, diff parsing, dispatch flow),
 * so no React/browser transform is needed. Keeping the config minimal avoids
 * a vite plugin-version coupling that adds nothing here.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["tests/web/**/*.test.ts"],
    reporters: ["default"],
  },
});
