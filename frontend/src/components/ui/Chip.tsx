/**
 * One chip vocabulary for every label tag in the product (DESIGN.md >
 * Badges, chips and bars): 20 px tall, 8 px padding, pill radius,
 * 11/16 semibold label, 12 px icon. Tone is carried by the caller as a
 * border/background/text triple on top of `CHIP_CLASS`.
 */
export const CHIP_CLASS =
  'inline-flex h-5 items-center gap-1 whitespace-nowrap rounded-full border px-2 text-2xs font-semibold leading-4'

/** The one icon size allowed inside a chip. */
export const CHIP_ICON = 12

/**
 * Interactive chip (protocol filters, view toggles): the same 11/16 semibold
 * label at the `sm` control height (28 px) so it lines up with `sm` buttons,
 * plus hover/active/pressed states.
 */
export const CHIP_ACTION_CLASS =
  'inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-2xs font-semibold transition-colors'
