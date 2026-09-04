import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "ZeroTrust-FL-Sim | Secure Federated Learning Dashboard",
  description: "Live control and observability dashboard for ZeroTrust-FL-Sim.",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
