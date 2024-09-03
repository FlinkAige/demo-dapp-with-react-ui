import { sha256 } from "@ton/crypto";
import { Address, Cell, contractAddress, loadStateInit } from "@ton/ton";
import { Buffer } from "buffer";
import { randomBytes, sign } from "tweetnacl";
import { CheckProofRequestDto } from "../dto/check-proof-request-dto";
import { tryParsePublicKey } from "../wrappers/wallets-data";
import { arrayToHex, SerialBuffer, hexToUint8Array } from '@amax/amaxjs-v2/dist/eosjs-serialize';

const tonProofPrefix = 'ton-proof-item-v2/';
const tonConnectPrefix = 'ton-connect';
const allowedDomains = [
  'ton-connect.github.io',
  'localhost:5173'
];
const validAuthTime = 15 * 60; // 15 minute

export class TonProofService {

  /**
   * Generate a random payload.
   */
  public generatePayload(): string {
    return Buffer.from(randomBytes(32)).toString('hex');
  }

  /**
   * Reference implementation of the checkProof method:
   * https://github.com/ton-blockchain/ton-connect/blob/main/requests-responses.md#address-proof-signature-ton_proof
   */
  public async checkProof(payload: CheckProofRequestDto, getWalletPublicKey: (address: string) => Promise<Buffer | null>): Promise<boolean> {
    console.log("CheckProofRequestDto", payload);
    try {
      const stateInit = loadStateInit(Cell.fromBase64(payload.proof.state_init).beginParse());

      // 1. First, try to obtain public key via get_public_key get-method on smart contract deployed at Address.
      // 2. If the smart contract is not deployed yet, or the get-method is missing, you need:
      //  2.1. Parse TonAddressItemReply.walletStateInit and get public key from stateInit. You can compare the walletStateInit.code
      //  with the code of standard wallets contracts and parse the data according to the found wallet version.
      let publicKey = tryParsePublicKey(stateInit) ?? await getWalletPublicKey(payload.address);
      if (!publicKey) {
        return false;
      }

      // 2.2. Check that TonAddressItemReply.publicKey equals to obtained public key
      const wantedPublicKey = Buffer.from(payload.public_key, 'hex');
      if (!publicKey.equals(wantedPublicKey)) {
        return false;
      }

      // 2.3. Check that TonAddressItemReply.walletStateInit.hash() equals to TonAddressItemReply.address. .hash() means BoC hash.
      const wantedAddress = Address.parse(payload.address);
      const address = contractAddress(wantedAddress.workChain, stateInit);
      if (!address.equals(wantedAddress)) {
        return false;
      }

      if (!allowedDomains.includes(payload.proof.domain.value)) {
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      if (now - validAuthTime > payload.proof.timestamp) {
        return false;
      }

      const message = {
        workchain: address.workChain,
        address: address.hash,
        domain: {
          lengthBytes: payload.proof.domain.lengthBytes,
          value: payload.proof.domain.value,
        },
        signature: Buffer.from(payload.proof.signature, 'base64'),
        payload: payload.proof.payload,
        stateInit: payload.proof.state_init,
        timestamp: payload.proof.timestamp
      };
      console.log("message", message);

      const wc = Buffer.alloc(4);
      wc.writeUInt32BE(message.workchain, 0);

      const ts = Buffer.alloc(8);
      ts.writeBigUInt64LE(BigInt(message.timestamp), 0);

      const dl = Buffer.alloc(4);
      dl.writeUInt32LE(message.domain.lengthBytes, 0);

      // const buf = new SerialBuffer({ textEncoder: new TextEncoder(), textDecoder: new TextDecoder() });
      // buf.pushPublicKey("AM7NQEt776J1HZmaMRyRRuY6ewcSFK63ZAKx1i9BY3WdSHiANxK2");
      // const amaxPayload = arrayToHex(buf.getUint8Array(34));
      // console.log("amaxPayload", amaxPayload);
      // console.log("hexToUint8Array(amaxPayload)", hexToUint8Array(amaxPayload));

      // message = utf8_encode("ton-proof-item-v2/") ++
      //           Address ++
      //           AppDomain ++
      //           Timestamp ++
      //           Payload
      const msg = Buffer.concat([
        Buffer.from(tonProofPrefix),
        wc,
        message.address,
        dl,
        Buffer.from(message.domain.value),
        ts,
        Buffer.from(message.payload),
        // hexToUint8Array(message.payload), // 验证不通过
      ]);
      // console.log("tonProofPrefix", tonProofPrefix);
      // console.log("tonProofPrefix2", Buffer.from(tonProofPrefix));
      // console.log("wc", wc.toString("hex"));
      console.log("address", message.address.toString("hex"));
      // console.log("dl", dl.toString("hex"));
      // console.log("domain", message.domain.value);
      // console.log("ts", ts.toString("hex"));
      console.log("payload", message.payload);
      console.log("msg", msg.toString("hex"));
      console.log("msg-str", msg.toString('utf8'));

      const msg_header1 = Buffer.concat([
        Buffer.from(tonProofPrefix),
        wc,
        message.address,
        dl,
        Buffer.from(message.domain.value),
        ts,
        // Buffer.from(message.payload),
      ]);
      console.log("msg_header1_hex", msg_header1.toString("hex")); // msg_header1_hex 合约参数1
      const msg_header1_sha256 = Buffer.from(await sha256(msg_header1));
      console.log("msg_header1_sha256", msg_header1_sha256.toString("hex"));

      const msgHash = Buffer.from(await sha256(msg));
      console.log("msgHash-sha256", msgHash.toString("hex"));

      // signature = Ed25519Sign(privkey, sha256(0xffff ++ utf8_encode("ton-connect") ++ sha256(message)))
      const fullMsg = Buffer.concat([
        Buffer.from([0xff, 0xff]),
        Buffer.from(tonConnectPrefix),
        msgHash,
      ]);
      console.log("fullMsg_hex", fullMsg.toString("hex"));

      const full_msg_head = Buffer.concat([
        Buffer.from([0xff, 0xff]),
        Buffer.from(tonConnectPrefix),
        // msgHash,
      ]);
      console.log("full_msg_head_hex", full_msg_head.toString("hex")); // full_msg_head_hex 合约参数2
      const full_msg_head_sha256 = Buffer.from(await sha256(full_msg_head));
      console.log("full_msg_head_sha256", full_msg_head_sha256.toString("hex"));

      const result = Buffer.from(await sha256(fullMsg));
      // console.log("message", result);
      console.log("message-hex", result.toString("hex"));

      // console.log("signature", message.signature)
      console.log("signature-hex", message.signature.toString("hex")) // 合约参数3

      // console.log("ton-publicKey", publicKey);
      console.log("ton-publicKey-hex", publicKey.toString("hex")); // 合约参数4

      const bool = sign.detached.verify(result, message.signature, publicKey);
      console.log("bool", bool);
      return bool;
    } catch (e) {
      console.log("[ERR]checkProof", e);
      return false;
    }
  }

}

// Private key: 5JDbxAwCnFhctqGByrKu6SasURR2sAYDb9gLfQJkBH4tyvbsJdY
// Public key: AM7NQEt776J1HZmaMRyRRuY6ewcSFK63ZAKx1i9BY3WdSHiANxK2


// const hello = Buffer.from(await sha256(Buffer.from("hello")));
// console.log("hello", Buffer.from("hello").toString());
// console.log("hello-hex", Buffer.from("hello").toString("hex"));
// console.log("hello-sha256", hello.toString("hex"));
