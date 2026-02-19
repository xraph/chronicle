"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

interface FeatureCard {
  title: string;
  description: string;
  icon: React.ReactNode;
  code: string;
  filename: string;
  colSpan?: number;
}

const features: FeatureCard[] = [
  {
    title: "Hash Chain Integrity",
    description:
      "Every event is linked by SHA-256 to its predecessor. Tamper any event and the chain breaks — Chronicle detects it instantly.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />
      </svg>
    ),
    code: `report, err := c.VerifyChain(ctx, &verify.Input{
  AppID:    "myapp",
  TenantID: "tenant-1",
})
// valid=true verified=842 gaps=[] tampered=[]`,
    filename: "verify.go",
  },
  {
    title: "GDPR Crypto-Erasure",
    description:
      "Per-subject AES-256-GCM encryption. Destroy the key — data becomes unrecoverable. Hash chain stays structurally valid.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
        <path d="M12 16v-2" />
      </svg>
    ),
    code: `result, _ := svc.Erase(ctx, &erasure.Input{
  SubjectID:   "user-42",
  Reason:      "GDPR Article 17",
  RequestedBy: "dpo@company.com",
}, "myapp", "tenant-1")
// key_destroyed=true events_affected=12`,
    filename: "erasure.go",
  },
  {
    title: "Compliance Reports",
    description:
      "Generate SOC2, HIPAA, EU AI Act, and custom reports with a single call. Export to JSON, CSV, Markdown, or HTML.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
      </svg>
    ),
    code: `report, _ := engine.SOC2(ctx, &compliance.SOC2Input{
  Period:      compliance.DateRange{
    From: q1Start, To: q1End,
  },
  AppID:       "myapp",
  GeneratedBy: "admin@company.com",
})`,
    filename: "compliance.go",
  },
  {
    title: "Multi-Tenant Isolation",
    description:
      "Scope middleware stamps every event with AppID and TenantID. Query isolation is enforced automatically — no cross-tenant data leaks.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" />
      </svg>
    ),
    code: `ctx = scope.WithAppID(ctx, "myapp")
ctx = scope.WithTenantID(ctx, "tenant-1")
ctx = scope.WithUserID(ctx, "user-42")

// All events and queries are
// automatically scoped to tenant-1`,
    filename: "scope.go",
  },
  {
    title: "Plugin System",
    description:
      "BeforeRecord and AfterRecord hooks let you enrich or drop events. AlertHandler fires in real time on matching severity or category.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M20.24 12.24a6 6 0 00-8.49-8.49L5 10.5V19h8.5z" />
        <line x1="16" y1="8" x2="2" y2="22" />
        <line x1="17.5" y1="15" x2="9" y2="15" />
      </svg>
    ),
    code: `func (p *MetricsPlugin) OnAfterRecord(
  ctx context.Context,
  ev *audit.Event,
) error {
  metrics.Inc("audit.event", ev.Severity)
  return nil
}`,
    filename: "plugin.go",
  },
  {
    title: "Pluggable Stores",
    description:
      "Start with in-memory for development, swap to PostgreSQL or Bun ORM for production. Implement your own store in ~36 methods.",
    icon: (
      <svg
        className="size-5"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4.03 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" />
      </svg>
    ),
    code: `c, _ := chronicle.New(
  chronicle.WithStore(
    store.NewAdapter(postgres.New(pool)),
  ),
  chronicle.WithCryptoErasure(true),
  chronicle.WithLogger(slog.Default()),
)`,
    filename: "main.go",
    colSpan: 2,
  },
];

const containerVariants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: "easeOut" as const },
  },
};

export function FeatureBento() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Features"
          title="Everything you need for audit trails"
          description="Chronicle handles the hard parts — hash chains, GDPR erasure, compliance reports, multi-tenancy — so you can focus on your business logic."
        />

        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-50px" }}
          className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          {features.map((feature) => (
            <motion.div
              key={feature.title}
              variants={itemVariants}
              className={cn(
                "group relative rounded-xl border border-fd-border bg-fd-card/50 backdrop-blur-sm p-6 hover:border-amber-500/20 hover:bg-fd-card/80 transition-all duration-300",
                feature.colSpan === 2 && "md:col-span-2",
              )}
            >
              {/* Header */}
              <div className="flex items-start gap-3 mb-4">
                <div className="flex items-center justify-center size-9 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400 shrink-0">
                  {feature.icon}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-fd-foreground">
                    {feature.title}
                  </h3>
                  <p className="text-xs text-fd-muted-foreground mt-1 leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              </div>

              {/* Code snippet */}
              <CodeBlock
                code={feature.code}
                filename={feature.filename}
                showLineNumbers={false}
                className="text-xs"
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}
