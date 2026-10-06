import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium font-mono transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-slate-200 bg-slate-100 text-slate-700 hover:bg-slate-200",
        secondary:
          "border-slate-100 bg-slate-50 text-slate-600 hover:bg-slate-100",
        outline:
          "text-slate-600 border border-slate-200 bg-white",
        low:
          "bg-slate-100 text-slate-700 border border-slate-200",
        medium:
          "bg-amber-50 text-amber-800 border border-amber-200",
        high:
          "bg-orange-50 text-orange-800 border border-orange-200",
        critical:
          "bg-red-50 text-red-700 border border-red-200 font-semibold shadow-sm",
        live:
          "bg-emerald-50 text-emerald-700 border border-emerald-200",
        brand:
          "bg-brand-50 text-brand-700 border border-brand-200",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
