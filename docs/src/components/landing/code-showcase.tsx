"use client";

import { motion } from "framer-motion";
import { CodeBlock } from "./code-block";
import { SectionHeader } from "./section-header";

const recordCode = `package main

import (
  "log/slog"
  "github.com/xraph/chronicle"
  "github.com/xraph/chronicle/scope"
  "github.com/xraph/chronicle/store"
  "github.com/xraph/chronicle/store/postgres"
)

func main() {
  pgStore := postgres.New(pool)
  c, _ := chronicle.New(
    chronicle.WithStore(store.NewAdapter(pgStore)),
    chronicle.WithCryptoErasure(true),
    chronicle.WithLogger(slog.Default()),
  )

  ctx = scope.WithAppID(ctx, "myapp")
  ctx = scope.WithTenantID(ctx, "tenant-1")
  ctx = scope.WithUserID(ctx, "user-42")

  // Record a tamper-proof audit event
  err = c.Warning(ctx, "perm.escalate", "role", "admin").
    Category("access").
    SubjectID("user-42").
    Meta("from", "viewer").
    Meta("to", "admin").
    Record()
}`;

const verifyCode = `package main

import (
  "fmt"
  "github.com/xraph/chronicle/verify"
)

func auditVerify(c *chronicle.Chronicle, ctx context.Context) {
  // Verify the full hash chain for a tenant
  report, err := c.VerifyChain(ctx, &verify.Input{
    AppID:    "myapp",
    TenantID: "tenant-1",
  })
  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf(
    "valid=%v verified=%d gaps=%v tampered=%v\\n",
    report.Valid,
    report.Verified,
    report.Gaps,
    report.Tampered,
  )
  // valid=true verified=8420 gaps=[] tampered=[]
}`;

export function CodeShowcase() {
  return (
    <section className="relative w-full py-20 sm:py-28">
      <div className="container max-w-(--fd-layout-width) mx-auto px-4 sm:px-6">
        <SectionHeader
          badge="Developer Experience"
          title="Simple API. Tamper-proof records."
          description="Record your first audit event in under 20 lines. Verify the entire hash chain with a single call."
        />

        <div className="mt-14 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recording side */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-amber-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Recording
              </span>
            </div>
            <CodeBlock code={recordCode} filename="main.go" />
          </motion.div>

          {/* Verification side */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <div className="mb-3 flex items-center gap-2">
              <div className="size-2 rounded-full bg-green-500" />
              <span className="text-xs font-medium text-fd-muted-foreground uppercase tracking-wider">
                Verification
              </span>
            </div>
            <CodeBlock code={verifyCode} filename="verify.go" />
          </motion.div>
        </div>
      </div>
    </section>
  );
}
