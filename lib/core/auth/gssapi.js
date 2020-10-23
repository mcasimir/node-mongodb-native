const dns = require('dns');
const util = require('util');

const AuthProvider = require('./auth_provider').AuthProvider;
const retrieveKerberos = require('../utils').retrieveKerberos;
const MongoError = require('../error').MongoError;

const kGssapiClientCache = Symbol('GSSAPI_CLIENT_CACHE');

let kerberos;

class GSSAPI extends AuthProvider {
  prepare(handshakeDoc, authContext, callback) {
    if (!this[kGssapiClientCache]) {
      this[kGssapiClientCache] = new Map();
    }

    prepare(this[kGssapiClientCache], handshakeDoc, authContext, callback);
  }

  auth(authContext, callback) {
    auth(this[kGssapiClientCache], authContext, callback);
  }
}
module.exports = GSSAPI;

// This should avoid `prepare` and `auth` calls to race both among each other and
// among other calls of the same function.
let lastCall = Promise.resolve();
function serializeCalls(fn) {
  if (!lastCall) {
    lastCall = Promise.resolve();
  }

  return async(...args) => {
    lastCall = lastCall.then(() => {
      return fn(...args);
    });

    return lastCall;
  };
}

// eslint-disable-next-line complexity
const prepare = util.callbackify(serializeCalls(async(clients, handshakeDoc, authContext) => {
  if (clients.get(authContext)) { // already prepared for that context
    return handshakeDoc;
  }

  const host = authContext.options.host;
  const port = authContext.options.port;
  const credentials = authContext.credentials;
  if (!host || !port || !credentials) {
    throw new MongoError(
      `Connection must specify: ${host ? 'host' : ''}, ${port ? 'port' : ''}, ${
        credentials ? 'host' : 'credentials'
      }.`
    );
  }

  const username = credentials.username;
  const password = credentials.password;
  const mechanismProperties = credentials.mechanismProperties;
  const serviceName =
      mechanismProperties.gssapiservicename ||
      mechanismProperties.gssapiServiceName ||
      'mongodb';

  kerberos = kerberos || retrieveKerberos();

  const initializeClient = util.promisify(kerberos.initializeClient.bind(kerberos));

  const canonicalizedHost = await performGssapiCanonicalizeHostName(host, mechanismProperties);

  const initOptions = {};
  if (password) {
    Object.assign(initOptions, { user: username, password: password });
  }

  const client = await initializeClient(
    `${serviceName}${process.platform === 'win32' ? '/' : '@'}${canonicalizedHost}`,
    initOptions
  );

  if (!client) {
    return; // this is translated from `if (!client) return callback();`.
    // No idea why we don't throw an error here.
  }

  clients.set(authContext, client);
  return handshakeDoc;
}));

const auth = util.callbackify(serializeCalls(async(clients, authContext) => {
  const client = clients.get(authContext);

  if (!client) {
    throw new MongoError('GSSAPI: client missing');
  }

  const connection = authContext.connection;
  const credentials = authContext.credentials;

  if (!credentials) {
    throw new MongoError('GSSAPI: credentials required');
  }

  const username = credentials.username;

  const externalCommand = util.promisify((command, cb) => {
    return connection.command('$external.$cmd', command, cb);
  });

  const clientStep = util.promisify(client.step.bind(client));

  const stepPayload = await (clientStep('').catch(adaptKerberosError()));

  const saslStartCommand = saslStart(stepPayload);
  const { result: saslStartResult } = await externalCommand(
    saslStartCommand
  );

  const negotiationPayload = await (negotiate(
    client, 10, saslStartResult.payload).catch(adaptKerberosError()));

  const { result: saslContinueResult } = await externalCommand(
    saslContinue(negotiationPayload, saslStartResult.conversationId)
  );

  const finalizePayload = await (finalize(
    client, username, saslContinueResult.payload
  ).catch(adaptKerberosError()));

  return await externalCommand(
    {
      saslContinue: 1,
      conversationId: saslContinueResult.conversationId,
      payload: finalizePayload
    }
  );
}));

// Errors coming from the kerberos module does not have
// a stack and are quite confusing as they always end with a ': Success' and
// there is nothing suggesting a GSSAPI failure.
//
// Also in electron a random amount of garbage characters gets pulled
// in the message.
//
// This is an attempt to improve the situation a bit, however all of this should
// better be done properly in the kerberos module.
//
function adaptKerberosError() {
  return (err) => {
    let message = err && err.message;

    if (!message) message = 'Unknown Kerberos Error';
    message = message.replace(/: Success.*/, '');
    message = `GSSAPI: ${message}`;

    return Promise.reject(new MongoError(message));
  };
}

function saslStart(payload) {
  return {
    saslStart: 1,
    mechanism: 'GSSAPI',
    payload,
    autoAuthorize: 1
  };
}
function saslContinue(payload, conversationId) {
  return {
    saslContinue: 1,
    conversationId,
    payload
  };
}
function negotiateCb(client, retries, payload, callback) {
  client.step(payload, (err, response) => {
    // Retries exhausted, raise error
    if (err && retries === 0) return callback(err);
    // Adjust number of retries and call step again
    if (err) return negotiateCb(client, retries - 1, payload, callback);
    // Return the payload
    callback(undefined, response || '');
  });
}

const negotiate = util.promisify(negotiateCb);

function finalizeCb(client, user, payload, callback) {
  // GSS Client Unwrap
  client.unwrap(payload, (err, response) => {
    if (err) return callback(err);
    // Wrap the response
    client.wrap(response || '', { user }, (wrapErr, wrapped) => {
      if (wrapErr) return callback(wrapErr);
      // Return the payload
      callback(undefined, wrapped);
    });
  });
}

const finalize = util.promisify(finalizeCb);

function performGssapiCanonicalizeHostNameCb(host, mechanismProperties, callback) {
  const canonicalizeHostName =
    typeof mechanismProperties.gssapiCanonicalizeHostName === 'boolean'
      ? mechanismProperties.gssapiCanonicalizeHostName
      : false;
  if (!canonicalizeHostName) return callback(undefined, host);
  // Attempt to resolve the host name
  dns.resolveCname(host, (err, r) => {
    if (err) return callback(err);
    // Get the first resolve host id
    if (Array.isArray(r) && r.length > 0) {
      return callback(undefined, r[0]);
    }
    callback(undefined, host);
  });
}

const performGssapiCanonicalizeHostName = util.promisify(performGssapiCanonicalizeHostNameCb);
