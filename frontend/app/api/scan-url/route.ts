import { NextRequest, NextResponse } from "next/server";

// Server-side proxy so the real backend key (SCAN_API_KEY) never ships to
// the browser. SCAN_BOX_PASSWORD gates who can use it -- unset locally on
// purpose, so local dev stays frictionless; only the hosted deploy sets it.
export async function POST(req: NextRequest) {
  const { url, password } = await req.json();

  const requiredPassword = process.env.SCAN_BOX_PASSWORD;
  if (requiredPassword && password !== requiredPassword) {
    return NextResponse.json({ detail: "Wrong password" }, { status: 401 });
  }

  const backendUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";
  const apiKey = process.env.SCAN_API_KEY;

  const res = await fetch(`${backendUrl}/scan/url`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { "X-API-Key": apiKey } : {}),
    },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
