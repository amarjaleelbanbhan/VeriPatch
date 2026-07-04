import { getSymbols } from './symbols.js';
import type { UiOptions } from './format.js';

const HIDE_CURSOR = '[?25l';
const SHOW_CURSOR = '[?25h';
const CLEAR_LINE = '\r[2K';
const FRAME_INTERVAL_MS = 80;

/**
 * A single-line progress indicator on stderr (stdout stays reserved for
 * `--json`/piped machine output, per the CLI's own contract). Deliberately a
 * no-op when stderr isn't a real TTY: a redirected log file or CI artifact
 * should never end up full of "\r" frames — that's the exact "ugly log"
 * failure mode this whole redesign exists to avoid. `veripatch scan > out.txt`
 * or a CI run produces zero spinner bytes, only the final report.
 */
export class Spinner {
  private readonly interactive: boolean;
  private readonly frames: string[];
  private timer: ReturnType<typeof setInterval> | undefined;
  private frameIndex = 0;
  private currentText = '';

  constructor(
    options: Pick<UiOptions, 'unicode' | 'color'>,
    private readonly stream: NodeJS.WriteStream = process.stderr,
  ) {
    this.interactive = stream.isTTY && options.color;
    this.frames = getSymbols(options.unicode).spinnerFrames;
  }

  start(text: string): void {
    this.currentText = text;
    if (!this.interactive) return;
    this.stream.write(HIDE_CURSOR);
    this.render();
    this.timer = setInterval(() => {
      this.frameIndex = (this.frameIndex + 1) % this.frames.length;
      this.render();
    }, FRAME_INTERVAL_MS);
  }

  update(text: string): void {
    this.currentText = text;
    if (this.interactive) this.render();
  }

  /** Clears the spinner line and, if provided, prints a final one-line status in its place. */
  stop(finalLine?: string): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
    if (this.interactive) {
      this.stream.write(CLEAR_LINE + SHOW_CURSOR);
    }
    if (finalLine !== undefined) this.stream.write(finalLine + '\n');
  }

  private render(): void {
    const frame = this.frames[this.frameIndex] ?? this.frames[0] ?? '';
    this.stream.write(`${CLEAR_LINE}${frame} ${this.currentText}`);
  }
}
