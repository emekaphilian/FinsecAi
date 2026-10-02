"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { clearToken, setActiveTenantId } from "@/lib/api";

const links = [
  { href: "/demo", label: "Overview" },
  { href: "/demo/incidents", label: "Incidents" },
  { href: "/demo/analytics", label: "Analytics" },
  { href: "/demo/copilot", label: "Copilot" },
  { href: "/demo/reports", label: "Reports" },
  { href: "/dashboard/governance", label: "Governance" },
];

export function DemoSidebar() {
  const pathname = usePathname();
  const router = useRouter();

  function logout() {
    clearToken();
    setActiveTenantId(null);
    router.push("/");
  }

  return (
    <aside className="w-64 border-r border-border min-h-screen p-4">
      <div className="mb-8">
        <p className="text-xs uppercase tracking-wide text-gold">
          FinSecAI
        </p>

        <h2 className="font-semibold mt-1">
          Acme Demo
        </h2>
      </div>

      <nav className="space-y-1">
        {links.map((link) => {
          const active =
            link.href === "/demo"
              ? pathname === "/demo"
              : pathname.startsWith(link.href);

          return (
            <Link
              key={link.href}
              href={link.href}
              className={
                active
                  ? "block px-3 py-2 rounded-md bg-surface text-gold"
                  : "block px-3 py-2 rounded-md text-text-secondary hover:text-gold"
              }
            >
              {link.label}
            </Link>
          );
        })}
      </nav>

      <button
        type="button"
        onClick={logout}
        className="mt-8 text-sm text-text-secondary hover:text-gold"
      >
        Exit Demo
      </button>
    </aside>
  );
}
