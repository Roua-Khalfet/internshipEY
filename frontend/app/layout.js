import "./globals.css";

export const metadata = {
  title: "SOC Copilot — AI Security Dashboard",
  description: "AI-powered intrusion detection and threat intelligence dashboard combining XGBoost ML predictions with Nuclei vulnerability intelligence.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
