import {
  repeatString,
  createPaymentMessage,
  sortOutputs,
  mapAPI,
  sign,
  toPublicKey,
  getHeadersSize,
  getTotalPayloadSize,
  getBase64Hash,
  getUnitHashToSign,
  getUnitHash,
} from './internal';
import { getChash160, fromWif } from './utils';
import WSClient from './wsclient';
import { DEFAULT_NODE, VERSION, VERSION_TESTNET, ALT, ALT_TESTNET } from './constants';
import api from './api.json';
import apps from './apps.json';

export default class Client {
  constructor(nodeAddress = DEFAULT_NODE, clientOptions = {}) {
    const self = this;

    this.options = typeof clientOptions === 'object' ? clientOptions : { testnet: clientOptions };
    this.client = new WSClient(nodeAddress);
    this.cachedWitnesses = null;

    const requestAsync = (name, params) =>
      new Promise((resolve, reject) => {
        this.client.request(name, params, (err, result) => {
          if (err) return reject(err);
          return resolve(result);
        });
      });

    this.api = {};

    this.compose = {
      async message(app, payload, options = {}) {
        const conf =
          typeof options === 'object'
            ? { ...self.options, ...options }
            : { ...self.options, wif: options };
        const privKeyBuf = fromWif(conf.wif, conf.testnet).privateKey;
        const pubkey = toPublicKey(privKeyBuf);
        const signerDefinition = ['sig', { pubkey }];
        const signerAddress = getChash160(signerDefinition);
        const definition = conf.definition || signerDefinition;
        const address = conf.address || getChash160(definition);
        const path = conf.path || 'r';
        const isMultiAuthored = signerAddress !== address;

        const bytePayment = await createPaymentMessage(
          self,
          null,
          app !== 'payment' || payload.asset ? [] : payload.outputs,
          address,
          isMultiAuthored ? signerAddress : null,
        );
        const customMessages = [bytePayment];

        if (app === 'payment') {
          if (payload.asset) {
            const assetPayment = await createPaymentMessage(
              self,
              payload.asset,
              payload.outputs,
              address,
            );
            customMessages.push(assetPayment);
          }
        } else {
          customMessages.push({
            app,
            payload_hash: getBase64Hash(payload),
            payload_location: 'inline',
            payload,
          });
        }

        const witnesses = await self.getCachedWitnesses();
        const [lightProps, networkDefinition, signerNetworkDefinition] = await Promise.all([
          self.api.getParentsAndLastBallAndWitnessListUnit({ witnesses }),
          self.api.getDefinition(address),
          isMultiAuthored ? self.api.getDefinition(signerAddress) : null,
        ]);

        const unit = {
          version: conf.testnet ? VERSION_TESTNET : VERSION,
          alt: conf.testnet ? ALT_TESTNET : ALT,
          messages: [...customMessages],
          authors: [],
          parent_units: lightProps.parent_units,
          last_ball: lightProps.last_stable_mc_ball,
          last_ball_unit: lightProps.last_stable_mc_ball_unit,
          witness_list_unit: lightProps.witness_list_unit,
        };

        unit.authors.push({
          address,
          authentifiers: { r: repeatString('-', 88) },
          definition: !networkDefinition ? definition : undefined,
        });

        if (isMultiAuthored) {
          unit.authors.push({
            address: signerAddress,
            authentifiers: { r: repeatString('-', 88) },
            definition: !signerNetworkDefinition ? signerDefinition : undefined,
          });

          unit.earned_headers_commission_recipients = [
            {
              address: signerAddress,
              earned_headers_commission_share: 100,
            },
          ];
        }

        unit.headers_commission = getHeadersSize(unit);
        unit.payload_commission = getTotalPayloadSize(unit);

        customMessages[0].payload.outputs[0].amount -=
          unit.headers_commission + unit.payload_commission;
        customMessages[0].payload.outputs.sort(sortOutputs);
        customMessages[0].payload_hash = getBase64Hash(customMessages[0].payload);

        if (payload.asset) {
          customMessages[1].payload.outputs.sort(sortOutputs);
          customMessages[1].payload_hash = getBase64Hash(customMessages[1].payload);
        }

        const textToSign = getUnitHashToSign(unit);
        const signature = sign(textToSign, privKeyBuf);
        unit.authors[0].authentifiers = {};
        unit.authors[0].authentifiers[path] = signature;
        if (isMultiAuthored) {
          unit.authors[1].authentifiers = { r: signature };
        }

        unit.messages = [...customMessages];
        unit.unit = getUnitHash(unit);

        return unit;
      },
    };

    this.post = {
      async message(app, payload, options) {
        const unit = await self.compose.message(app, payload, options);
        return self.broadcast(unit);
      },
    };

    Object.assign(this.api, mapAPI(api, requestAsync));
    Object.assign(this.compose, mapAPI(apps, this.compose.message));
    Object.assign(this.post, mapAPI(apps, this.post.message));
  }

  async broadcast(unit) {
    await this.api.postJoint({ unit });
    return unit.unit;
  }

  async getCachedWitnesses() {
    if (this.cachedWitnesses) return this.cachedWitnesses;

    this.cachedWitnesses = await this.api.getWitnesses();
    return this.cachedWitnesses;
  }

  subscribe(cb) {
    this.client.subscribe(cb);
  }

  justsaying(subject, body) {
    this.client.justsaying(subject, body);
  }

  close() {
    this.client.close();
  }
}
