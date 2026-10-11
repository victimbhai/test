import { redirect } from "next/navigation";

/**
 * Root route.
 *
 * The dashboard is private by default, so the root redirects to sign-in. An
 * authenticated session is then forwarded on to the overview by the dashboard
 * shell.
 */
export default function Home() {
  redirect("/login");
}
