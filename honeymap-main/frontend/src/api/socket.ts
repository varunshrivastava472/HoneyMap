/**
 * HoneyMap Dual-Transport Event Stream (WebSocket + Polling Fallback)
 * Path: frontend/src/api/socket.ts
 */

import { io, Socket } from 'socket.io-client';
import { fetchEvents } from './client';
import { TelemetryEvent } from '../types';

const SOCKET_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SOCKET_URL) ||
  'http://localhost:5000';

const NO_EVENT_TIMEOUT_MS = 5000; // 5s watchdog timeout
const POLLING_INTERVAL_MS = 3000; // 3s polling interval
const MAX_SEEN_SET_SIZE = 10000; // Keep Set memory bounded

export type TransportType = 'websocket' | 'polling' | 'disconnected' | 'connecting';
export type EventSubscriber = (event: TelemetryEvent, transport: 'websocket' | 'polling') => void;
export type StatusSubscriber = (status: TransportType) => void;

class EventStreamManager {
  private socket: Socket | null = null;
  private subscribers: Set<EventSubscriber> = new Set();
  private statusSubscribers: Set<StatusSubscriber> = new Set();
  private seenEventIds: Set<number> = new Set();
  private lastSeenTimestamp: string | null = null;

  public activeTransport: TransportType = 'connecting';
  private watchdogTimer: ReturnType<typeof setTimeout> | null = null;
  private pollingIntervalTimer: ReturnType<typeof setInterval> | null = null;
  private isPollingActive = false;
  private isPollingFetchInProgress = false;

  constructor() {
    this.initSocket();
  }

  /**
   * Initializes Socket.IO connection and attaches lifecycle listeners.
   */
  private initSocket() {
    try {
      this.socket = io(SOCKET_URL, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        timeout: 4000,
      });

      this.socket.on('connect', () => {
        this.setTransport('websocket');
        this.resetWatchdogTimer();
      });

      this.socket.on('new_event', (event: TelemetryEvent) => {
        this.resetWatchdogTimer();
        this.stopPolling();
        this.setTransport('websocket');
        this.dispatch(event, 'websocket');
      });

      this.socket.on('system_reset', () => {
        this.seenEventIds.clear();
        this.lastSeenTimestamp = null;
        if (typeof window !== 'undefined') {
          window.location.reload();
        }
      });

      this.socket.on('connect_error', () => {
        this.triggerPollingFallback();
      });

      this.socket.on('disconnect', () => {
        this.triggerPollingFallback();
      });

      this.socket.on('error', () => {
        this.triggerPollingFallback();
      });

      this.resetWatchdogTimer();
    } catch {
      this.triggerPollingFallback();
    }
  }

  private resetWatchdogTimer() {
    if (this.watchdogTimer) {
      clearTimeout(this.watchdogTimer);
    }
    this.watchdogTimer = setTimeout(() => {
      this.triggerPollingFallback();
    }, NO_EVENT_TIMEOUT_MS);
  }

  private triggerPollingFallback() {
    if (!this.isPollingActive) {
      this.startPolling();
    }
  }

  private startPolling() {
    this.isPollingActive = true;
    this.setTransport('polling');

    if (this.pollingIntervalTimer) {
      clearInterval(this.pollingIntervalTimer);
    }

    this.pollEvents();
    this.pollingIntervalTimer = setInterval(() => {
      this.pollEvents();
    }, POLLING_INTERVAL_MS);
  }

  private stopPolling() {
    if (this.pollingIntervalTimer) {
      clearInterval(this.pollingIntervalTimer);
      this.pollingIntervalTimer = null;
    }
    this.isPollingActive = false;
  }

  private async pollEvents() {
    if (this.isPollingFetchInProgress) return;
    this.isPollingFetchInProgress = true;

    try {
      const data = await fetchEvents({
        limit: 50,
        since: this.lastSeenTimestamp || undefined,
      });

      if (data && Array.isArray(data.events)) {
        for (const event of data.events) {
          this.dispatch(event, 'polling');
        }
      }
    } catch (err) {
      console.warn('[HoneyMap Fallback] Polling error:', err);
    } finally {
      this.isPollingFetchInProgress = false;
    }
  }

  private setTransport(transport: TransportType) {
    if (this.activeTransport !== transport) {
      this.activeTransport = transport;
      this.notifyStatusSubscribers(transport);
    }
  }

  private dispatch(event: TelemetryEvent, transport: 'websocket' | 'polling') {
    if (!event || typeof event.id === 'undefined') return;

    if (this.seenEventIds.has(event.id)) {
      return;
    }

    this.seenEventIds.add(event.id);
    if (this.seenEventIds.size > MAX_SEEN_SET_SIZE) {
      const firstEntries = Array.from(this.seenEventIds).slice(0, 1000);
      for (const oldId of firstEntries) {
        this.seenEventIds.delete(oldId);
      }
    }

    if (event.timestamp) {
      this.lastSeenTimestamp = event.timestamp;
    }

    for (const sub of this.subscribers) {
      try {
        sub(event, transport);
      } catch (err) {
        console.error('[HoneyMap] Subscriber dispatch error:', err);
      }
    }
  }

  public subscribe(fn: EventSubscriber): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  public subscribeStatus(fn: StatusSubscriber): () => void {
    this.statusSubscribers.add(fn);
    fn(this.activeTransport);
    return () => this.statusSubscribers.delete(fn);
  }

  private notifyStatusSubscribers(status: TransportType) {
    for (const sub of this.statusSubscribers) {
      try {
        sub(status);
      } catch (err) {
        console.error('[HoneyMap] Status subscriber error:', err);
      }
    }
  }

  public destroy() {
    if (this.watchdogTimer) clearTimeout(this.watchdogTimer);
    if (this.pollingIntervalTimer) clearInterval(this.pollingIntervalTimer);
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.subscribers.clear();
    this.statusSubscribers.clear();
    this.seenEventIds.clear();
  }
}

let instance: EventStreamManager | null = null;

function getStreamManager(): EventStreamManager {
  if (!instance) {
    instance = new EventStreamManager();
  }
  return instance;
}

export function subscribeToEvents(fn: EventSubscriber): () => void {
  return getStreamManager().subscribe(fn);
}

export function subscribeToTransportStatus(fn: StatusSubscriber): () => void {
  return getStreamManager().subscribeStatus(fn);
}

export function getActiveTransport(): TransportType {
  return getStreamManager().activeTransport;
}
