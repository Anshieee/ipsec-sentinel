import { useReducedMotion } from 'framer-motion'

/**
 * `useReducedMotion` from framer-motion returns `null` while unknown;
 * this wrapper always answers with a boolean so branches stay simple.
 */
export function useReducedMotionSafe(): boolean {
  return useReducedMotion() === true
}
