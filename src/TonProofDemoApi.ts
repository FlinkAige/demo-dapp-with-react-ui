import {
  Account,
  ConnectAdditionalRequest,
  SendTransactionRequest,
  TonProofItemReplySuccess
} from "@tonconnect/ui-react";
import './patch-local-storage-for-github-pages';
import {CreateJettonRequestDto} from "./server/dto/create-jetton-request-dto";
import { arrayToHex, SerialBuffer, hexToUint8Array } from '@amax/amaxjs-v2/dist/eosjs-serialize';

class TonProofDemoApiService {
  private localStorageKey = 'demo-api-access-token';

  private host = document.baseURI.replace(/\/$/, '');

  public accessToken: string | null = null;

  public readonly refreshIntervalMs = 9 * 60 * 1000;

  constructor() {
    this.accessToken = localStorage.getItem(this.localStorageKey);

    if (!this.accessToken) {
      this.generatePayload();
    }
  }

  async generatePayload(): Promise<ConnectAdditionalRequest | null> {
    try {
      const response = await (
        await fetch(`${this.host}/api/generate_payload`, {
          method: 'POST',
        })
      ).json();
      // return {tonProof: response.payload as string};
      // return {tonProof: "AM7NQEt776J1HZmaMRyRRuY6ewcSFK63ZAKx1i9BY3WdSHiANxK2"};

      const buf = new SerialBuffer({ textEncoder: new TextEncoder(), textDecoder: new TextDecoder() });
      buf.pushPublicKey("AM7NQEt776J1HZmaMRyRRuY6ewcSFK63ZAKx1i9BY3WdSHiANxK2");
      const amaxPayload = arrayToHex(buf.getUint8Array(34));
      console.log("amaxPayload", amaxPayload);
      return {tonProof: amaxPayload.toString()};
    } catch {
      return null;
    }
  }

  async checkProof(proof: TonProofItemReplySuccess['proof'], account: Account): Promise<void> {
    try {
      const reqBody = {
        address: account.address,
        network: account.chain,
        public_key: account.publicKey,
        proof: {
          ...proof,
          state_init: account.walletStateInit,
        },
      };

      const response = await (
        await fetch(`${this.host}/api/check_proof`, {
          method: 'POST',
          body: JSON.stringify(reqBody),
        })
      ).json();

      if (response?.token) {
        localStorage.setItem(this.localStorageKey, response.token);
        this.accessToken = response.token;
      }
    } catch (e) {
      console.log('checkProof error:', e);
    }
  }

  async getAccountInfo(account: Account) {
    const response = await (
      await fetch(`${this.host}/api/get_account_info`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
      })
    ).json();

    return response as {};
  }

  async createJetton(jetton: CreateJettonRequestDto): Promise<SendTransactionRequest> {
    return await (
      await fetch(`${this.host}/api/create_jetton`, {
        body: JSON.stringify(jetton),
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        method: 'POST',
      })
    ).json();
  }

  reset() {
    this.accessToken = null;
    localStorage.removeItem(this.localStorageKey);
    this.generatePayload();
  }
}

export const TonProofDemoApi = new TonProofDemoApiService();
