/**
 * VAJRA — Owner-Specific Real-Time Event Stream (SSE)
 * Prompt 0052: Real-time Owner Approval & Enrollment Recovery
 *
 * Provides authenticated, owner-filtered Server-Sent Events (SSE).
 * Invariants:
 * - Strictly filters events by authenticated user ID (no cross-tenant leakage).
 * - Events are dispatched only after DB commits.
 * - Payloads NEVER contain enrollment tokens, passcodes, challenge nonces, or private keys.
 * - Heartbeat comment pings (: ping\n\n) keep connection open through proxies/gateways.
 * - Cleans up connections on client close or socket error.
 */

import { Response } from 'express';

export type OwnerSseEventType =
  | 'DEVICE_AWAITING_APPROVAL'
  | 'DEVICE_CONNECTED'
  | 'DEVICE_REJECTED'
  | 'DEVICE_REVOKED'
  | 'SECURITY_ALERT';

export interface OwnerSseEvent<T = Record<string, unknown>> {
  type: OwnerSseEventType;
  userId: string;
  payload: T;
  timestamp: string;
}

export class OwnerEventBroadcaster {
  private static instance: OwnerEventBroadcaster | null = null;
  private connectionsByUser: Map<string, Set<Response>> = new Map();
  private pingInterval: NodeJS.Timeout | null = null;

  public static getInstance(): OwnerEventBroadcaster {
    if (!OwnerEventBroadcaster.instance) {
      OwnerEventBroadcaster.instance = new OwnerEventBroadcaster();
    }
    return OwnerEventBroadcaster.instance;
  }

  constructor() {
    // Keep connections alive across proxies with comment ping every 15 seconds
    this.pingInterval = setInterval(() => {
      this.sendKeepAlivePing();
    }, 15_000);
    // Allow process to exit cleanly during tests
    if (this.pingInterval.unref) {
      this.pingInterval.unref();
    }
  }

  /**
   * Registers an authenticated SSE connection for a specific user.
   */
  public registerClient(userId: string, res: Response): () => void {
    if (!this.connectionsByUser.has(userId)) {
      this.connectionsByUser.set(userId, new Set());
    }
    const userClients = this.connectionsByUser.get(userId)!;
    userClients.add(res);

    // Initial greeting comment
    res.write(`: connected at ${new Date().toISOString()}\n\n`);

    const cleanup = () => {
      userClients.delete(res);
      if (userClients.size === 0) {
        this.connectionsByUser.delete(userId);
      }
    };

    res.on('close', cleanup);
    res.on('error', cleanup);

    return cleanup;
  }

  /**
   * Dispatches an event strictly to the designated user's active SSE clients.
   */
  public emitToUser<T extends Record<string, unknown>>(
    userId: string,
    type: OwnerSseEventType,
    payload: T
  ): number {
    const clients = this.connectionsByUser.get(userId);
    if (!clients || clients.size === 0) {
      return 0;
    }

    const event: OwnerSseEvent<T> = {
      type,
      userId,
      payload,
      timestamp: new Date().toISOString(),
    };

    const message = `event: ${type}\ndata: ${JSON.stringify(event)}\n\n`;
    let delivered = 0;

    for (const res of Array.from(clients)) {
      try {
        if (!res.writableEnded && res.writable) {
          res.write(message);
          if (typeof (res as any).flush === 'function') {
            (res as any).flush();
          }
          delivered++;
        } else {
          clients.delete(res);
        }
      } catch {
        clients.delete(res);
      }
    }

    if (clients.size === 0) {
      this.connectionsByUser.delete(userId);
    }

    return delivered;
  }

  /**
   * Number of active client connections for a user.
   */
  public getClientCount(userId: string): number {
    return this.connectionsByUser.get(userId)?.size ?? 0;
  }

  /**
   * Sends heartbeat ping comment to all connected SSE clients.
   */
  private sendKeepAlivePing(): void {
    for (const [userId, clients] of this.connectionsByUser.entries()) {
      for (const res of Array.from(clients)) {
        try {
          if (!res.writableEnded && res.writable) {
            res.write(`: ping ${Date.now()}\n\n`);
            if (typeof (res as any).flush === 'function') {
              (res as any).flush();
            }
          } else {
            clients.delete(res);
          }
        } catch {
          clients.delete(res);
        }
      }
      if (clients.size === 0) {
        this.connectionsByUser.delete(userId);
      }
    }
  }

  /**
   * Clean up timer and close all active SSE connections for tests/shutdown.
   */
  public destroy(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    for (const clients of this.connectionsByUser.values()) {
      for (const res of Array.from(clients)) {
        try {
          res.end();
        } catch {
          // ignore
        }
      }
    }
    this.connectionsByUser.clear();
  }
}

export const ownerEventBroadcaster = OwnerEventBroadcaster.getInstance();
