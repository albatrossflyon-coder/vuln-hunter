import { NextRequest, NextResponse } from "next/server";

// Server-side proxy for GraphQL requests to the vuln-hunter backend.
// This route injects the SCAN_API_KEY from environment variables to keep it
// off the browser.
export async function POST(req: NextRequest) {
  const { query, variables } = await req.json();

  const backendUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";
  const apiKey = process.env.SCAN_API_KEY;

  try {
    const res = await fetch(`${backendUrl}/graphql`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      body: JSON.stringify({ query, variables }),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (error) {
    console.error("GraphQL proxy error:", error);
    return NextResponse.json(
      { error: "Failed to fetch GraphQL data", details: error instanceof Error ? error.message : String(error) },
      { status: 500 }
    );
  }
}
