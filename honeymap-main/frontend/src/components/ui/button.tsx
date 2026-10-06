import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-lg text-xs font-medium ring-offset-background transition-all duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 gap-1.5 cursor-pointer active:scale-95 hover:-translate-y-0.5 select-none",
  {
    variants: {
      variant: {
        default:
          "bg-brand-600 text-white hover:bg-brand-700 shadow-sm hover:shadow-md font-semibold hover:brightness-105",
        destructive:
          "bg-danger-600 text-white hover:bg-danger-700 shadow-sm hover:shadow-md hover:brightness-105",
        outline:
          "border border-slate-200 bg-white hover:bg-slate-50 hover:text-ink-primary hover:border-slate-300 text-ink-secondary shadow-sm hover:shadow",
        secondary:
          "bg-slate-100 text-ink-primary hover:bg-slate-200 border border-slate-200/60 shadow-sm",
        ghost:
          "hover:bg-slate-100 hover:text-ink-primary text-ink-secondary hover:translate-y-0",
        link:
          "text-brand-600 underline-offset-4 hover:underline hover:translate-y-0",
        accent:
          "bg-orange-500 text-white hover:bg-orange-600 shadow-sm hover:shadow-md font-semibold hover:brightness-105",
      },
      size: {
        default: "h-8 px-3.5 py-1.5",
        sm: "h-7 rounded-md px-2.5 text-[11px]",
        lg: "h-9 rounded-lg px-4",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
