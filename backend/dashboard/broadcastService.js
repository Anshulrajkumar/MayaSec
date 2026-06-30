/**
 * SSE broadcaster for the MayaSec dashboard.
 */
export class BroadcastService {
  constructor() {
    this.clients = [];
  }

  /**
   * @param {import('express').Response} res
   * @param {string} apiKey
   * @returns {void}
   */
  addClient(res, apiKey) {
    this.clients.push({ res, apiKey });
  }

  /**
   * @param {import('express').Response} res
   * @returns {void}
   */
  removeClient(res) {
    this.clients = this.clients.filter((client) => client.res !== res);
  }

  /**
   * @param {string} type
   * @param {unknown} payload
   * @param {string} apiKey
   * @returns {void}
   */
  broadcast(type, payload, apiKey) {
    this.clients.forEach((client) => {
      if (client.apiKey !== apiKey) return;
      client.res.write(`data: ${JSON.stringify({ type, data: payload })}\n\n`);
    });
  }
}

export const broadcastService = new BroadcastService();
