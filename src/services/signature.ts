import { HmacSHA1, enc } from "crypto-js";

export const requestTokenSignature = ({
  method,
  apiUrl,
  callbackUrl,
  consumerKey,
  consumerSecret
}: {
  method: string;
  apiUrl: string;
  callbackUrl: string;
  consumerKey: string;
  consumerSecret: string;
}) => {
  const params = {
    oauth_consumer_key: consumerKey,
    oauth_version: "1.0",
    oauth_signature_method: "HMAC-SHA1",
    oauth_callback: callbackUrl,
    oauth_timestamp: (Date.now() / 1000).toFixed(),
    oauth_nonce: Math.random()
      .toString(36)
      .replace(/[^a-z]/, "")
      .substr(2)
  };

  return makeSignature(params, method, apiUrl, consumerSecret);
};

export const accessTokenSignature = ({
  consumerKey,
  consumerSecret,
  oauthToken,
  oauthVerifier,
  method,
  apiUrl
}: {
  method: string;
  apiUrl: string;
  consumerKey: string;
  consumerSecret: string;
  oauthToken: string;
  oauthVerifier: string;
}) => {
  const params = {
    oauth_consumer_key: consumerKey,
    oauth_version: "1.0",
    oauth_signature_method: "HMAC-SHA1",
    oauth_token: oauthToken,
    oauth_verifier: oauthVerifier,
    oauth_timestamp: (Date.now() / 1000).toFixed(),
    oauth_nonce: Math.random()
      .toString(36)
      .replace(/[^a-z]/, "")
      .substr(2)
  };

  return makeSignature(params, method, apiUrl, consumerSecret);
};

export const accessResourceSignature = ({
  consumerKey,
  consumerSecret,
  oauthToken,
  oauthTokenSecret,
  method,
  apiUrl,
  include_email
}: {
  method: string;
  apiUrl: string;
  consumerKey: string;
  consumerSecret: string;
  oauthToken: string;
  oauthTokenSecret: string;
  include_email: string;
}) => {
  const params = {
    oauth_consumer_key: consumerKey,
    oauth_version: "1.0",
    oauth_signature_method: "HMAC-SHA1",
    oauth_token: oauthToken,
    oauth_timestamp: (Date.now() / 1000).toFixed(),
    oauth_nonce: Math.random()
      .toString(36)
      .replace(/[^a-z]/, "")
      .substr(2)
  };

  const queryParams = {
    include_email: include_email
  };

  return makeSignature(
    params,
    method,
    apiUrl,
    consumerSecret,
    oauthTokenSecret,
    queryParams
  );
};

const makeSignature = (
  params: any,
  method: string,
  apiUrl: string,
  consumerSecret: string,
  oauthTokenSecret?: string,
  queryParams?: any
) => {
  let paramsBaseString: string;

  let _params = params;
  if (queryParams) {
    _params = { ..._params, ...queryParams };
  }

  paramsBaseString = Object.keys(_params)
    .sort()
    .reduce((prev: string, el: any) => {
      return (prev += `&${el}=${_params[el]}`);
    }, "")
    .substr(1);

  const signatureBaseString = `${method.toUpperCase()}&${encodeURIComponent(
    apiUrl
  )}&${encodeURIComponent(paramsBaseString)}`;

  let signingKey = `${encodeURIComponent(consumerSecret)}&`;
  if (oauthTokenSecret) {
    signingKey = `${signingKey}${encodeURIComponent(oauthTokenSecret)}`;
  }

  const oauth_signature = enc.Base64.stringify(
    HmacSHA1(signatureBaseString, signingKey)
  );

  const paramsWithSignature = {
    ...params,
    oauth_signature: encodeURIComponent(oauth_signature)
  };

  return Object.keys(paramsWithSignature)
    .sort()
    .reduce((prev: string, el: any) => {
      return (prev += `,${el}="${paramsWithSignature[el]}"`);
    }, "")
    .substr(1);
};
