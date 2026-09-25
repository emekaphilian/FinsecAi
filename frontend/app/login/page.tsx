"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { getSession, login } from "@/lib/api";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const isDemo = searchParams.get("demo") === "1";
  const [email, setEmail] = useState("demo@finsecai.com");
  const [password, setPassword] = useState("demo");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await login(email.trim(), password, isDemo ? "demo" : "any");
      const session = getSession();
      if (result.must_change_password) router.push(`/change-credentials?next=${isDemo ? "/demo" : "/dashboard"}`);
      else if (isDemo) router.push("/demo");
      else if (session?.role === "owner") router.push("/owner");
      else router.push("/dashboard");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to sign in.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-primary px-6 py-16">
      <form onSubmit={handleSubmit} className="card mx-auto w-full max-w-sm p-6">
        <div className="mb-4 flex items-center justify-between">
          <p className="text-xs font-semibold uppercase tracking-wide text-gold">Demo access</p>
          <Link href="/" className="text-xs font-medium text-text-secondary hover:text-text-primary">Back to home</Link>
        </div>
        <h1 className="mt-2 text-2xl font-semibold">Sign in</h1>
        <p className="mt-1 text-sm text-text-secondary">FinSecAI SOC Command Center</p>
        <div className="mt-7"><label className="mb-1 block text-xs text-text-secondary">Email</label><input className="input w-full" value={email} onChange={(e) => setEmail(e.target.value)} type="email" required /></div>
        <div className="mt-4"><label className="mb-1 block text-xs text-text-secondary">Password</label><input className="input w-full" value={password} onChange={(e) => setPassword(e.target.value)} type="password" required /></div>
        {error && <p className="mt-4 text-sm text-danger">{error}</p>}
        <button className="btn-primary mt-6 w-full py-2.5" disabled={loading}>{loading ? "Signing in..." : "Sign in"}</button>
        <div className="mt-6 border-t border-border pt-4"><p className="text-xs font-semibold uppercase tracking-wide text-gold">Demo access</p><p className="mt-1 text-sm text-text-secondary">Acme demonstration environment</p></div>
      </form>
    </main>
  );
}

export default function LoginPage() {
  return <Suspense><LoginForm /></Suspense>;
}
