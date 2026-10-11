import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* CSS is compiled by @tailwindcss/postcss via postcss.config.mjs. */
  cacheComponents: true,
  partialPrefetching: true,

  /* Monaco is ~3MB and browser-only: keep it out of the server bundle. */
  serverExternalPackages: ["monaco-editor"],

  /* Fail the build on type errors instead of shipping them to Vercel. */
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
