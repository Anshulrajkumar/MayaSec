import { telemetryBuffer } from './buffer.js';

export function clearAggregatedEvents() {
  const buf = telemetryBuffer.getBuffer();
  
  // LOW events are discarded after aggregation
  buf.mouse = [];
  buf.clicks = [];
  buf.scrolls = [];
  buf.behaviour = []; // clear other low-value behaviour if needed
  
  // Medium and High events might be kept longer if needed, but typically they are flushed.
  // The sender will clear medium and high after transmission.
}
