import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vuln Hunter",
  description: "AI-assisted security code review — real static analysis, Claude triage",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full">
      <body className="h-full bg-white text-black antialiased" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
