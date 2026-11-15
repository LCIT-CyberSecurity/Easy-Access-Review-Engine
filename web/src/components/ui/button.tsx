import { Slot } from "radix-ui";
import type { ComponentProps } from "react";
import { cn } from "../../lib/utils";
import { buttonVariants, type ButtonVariantProps } from "./button-variants";

export type ButtonProps = ComponentProps<"button"> & ButtonVariantProps & { asChild?: boolean };

/** Native button semantics by default; `asChild` supports accessible links. */
export function Button({ className, variant, size, asChild = false, ...props }: ButtonProps) {
  const Component = asChild ? Slot.Root : "button";
  return <Component data-slot="button" className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
