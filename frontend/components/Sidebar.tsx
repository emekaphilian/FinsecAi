"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { clearToken, getSession } from "@/lib/api";

const links = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/incidents", label: "Incidents" },
  { href: "/dashboard/analytics", label: "Analytics" },
  { href: "/dashboard/copilot", label: "Copilot" },
  { href: "/dashboard/reports", label: "Reports" },
  { href: "/dashboard/governance", label: "Governance" },
];

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const selectedTenantId = searchParams.get("tenant_id");
  const tenantScope = selectedTenantId
    ? `?tenant_id=${encodeURIComponent(selectedTenantId)}`
    : "";

  return (
    <aside className="w-56 shrink-0 border-r border-border min-h-screen px-4 py-6 flex flex-col">
      <span className="text-lg font-semibold px-2 mb-8">
        FinSec<span className="text-gold">AI</span>
      </span>

      <nav className="flex-1 space-y-1">
        {links.map((link) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={`${link.href}${tenantScope}`}
              className={`block px-3 py-2 rounded-lg text-sm ${
                active
                  ? "bg-gold/15 text-gold font-medium"
                  : "text-text-secondary hover:bg-secondary hover:text-text-primary"
              }`}
            >
              {link.label}
            </Link>
          );
        })}
      </nav>

      <button
        onClick={() => {
          clearToken();
          router.push(getSession()?.role === "owner" ? "/owner-login" : "/tenant-login");
        }}
        className="text-sm text-text-secondary hover:text-danger px-3 py-2 text-left"
      >
        Sign out
      </button>
    </aside>
  );
}
