declare module 'culori' {
  export function converter(mode: string): (color: unknown) => unknown
  export function formatRgb(color: unknown): string
  export function parse(color: string): unknown
}
