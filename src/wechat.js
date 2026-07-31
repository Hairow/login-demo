// ============================================================
// 微信开放平台 — 网站应用扫码登录 OAuth 2.0
// 文档: https://developers.weixin.qq.com/doc/oplatform/Mobile_App/WeChat_Login/Development_Guide.html
// ============================================================

const AUTHORIZE_ENDPOINT = "https://open.weixin.qq.com/connect/qrconnect";
const TOKEN_ENDPOINT = "https://api.weixin.qq.com/sns/oauth2/access_token";

/**
 * 微信 OAuth 2.0 客户端
 *
 * 用法：
 *   const wechat = new WeChat(appId, appSecret, redirectUri);
 *   const url = wechat.createAuthorizationURL(state);
 *   const tokens = await wechat.validateAuthorizationCode(code);
 *   tokens.accessToken()  // => "access_token"
 *   tokens.openid()       // => "openid"
 */
export class WeChat {
  constructor(clientId, clientSecret, redirectUri) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
  }

  createAuthorizationURL(state) {
    const params = new URLSearchParams({
      appid: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: "code",
      scope: "snsapi_login",
      state,
    });
    return new URL(`${AUTHORIZE_ENDPOINT}?${params.toString()}#wechat_redirect`);
  }

  async validateAuthorizationCode(code) {
    const params = new URLSearchParams({
      appid: this.clientId,
      secret: this.clientSecret,
      code,
      grant_type: "authorization_code",
    });
    const resp = await fetch(`${TOKEN_ENDPOINT}?${params.toString()}`);
    const data = await resp.json();
    if (data.errcode) {
      throw new Error(`WeChat token error [${data.errcode}]: ${data.errmsg}`);
    }
    return new WeChatTokens(data.access_token, data.openid, data.unionid);
  }
}

/**
 * 微信 Token 响应容器
 * 与 arctic 设计一致：敏感字段通过方法获取，防止意外序列化泄露
 */
class WeChatTokens {
  #accessToken;
  #openid;
  #unionid;

  constructor(accessToken, openid, unionid) {
    this.#accessToken = accessToken;
    this.#openid = openid;
    this.#unionid = unionid;
  }

  accessToken() {
    return this.#accessToken;
  }

  openid() {
    return this.#openid;
  }

  /** unionid 为 null 时表示未绑定开放平台 */
  unionid() {
    return this.#unionid || null;
  }
}
