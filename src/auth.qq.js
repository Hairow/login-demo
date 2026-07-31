// ============================================================
// QQ互联 — 网站应用 OAuth 2.0
// 文档: https://wiki.connect.qq.com/oauth2-0开发文档
// ============================================================

const AUTHORIZE_ENDPOINT = "https://graph.qq.com/oauth2.0/authorize";
const TOKEN_ENDPOINT = "https://graph.qq.com/oauth2.0/token";

/**
 * QQ OAuth 2.0 客户端
 *
 * QQ token 响应默认是 callback 格式，需要显式加 fmt=json。
 *
 * 用法：
 *   const qq = new QQ(appId, appKey, redirectUri);
 *   const url = qq.createAuthorizationURL(state);
 *   const tokens = await qq.validateAuthorizationCode(code);
 *   tokens.accessToken()  // => "access_token"
 */
export class QQ {
  constructor(clientId, clientSecret, redirectUri) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
  }

  createAuthorizationURL(state) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: "get_user_info",// 关键：必须是 get_user_info
      state,
    });
    return new URL(`${AUTHORIZE_ENDPOINT}?${params.toString()}`);
  }

  async validateAuthorizationCode(code) {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: this.redirectUri,
      fmt: "json", // 关键：强制返回 JSON，否则默认是 callback(...)
    });
    const resp = await fetch(`${TOKEN_ENDPOINT}?${params.toString()}`);
    const body = await resp.text();

    let data;
    try {
      data = JSON.parse(body);
    } catch {
      throw new Error(`QQ token response is not valid JSON: ${body.substring(0, 200)}`);
    }

    if (data.error) {
      throw new Error(`QQ token error: ${data.error_description || data.error}`);
    }

    return new QQTokens(data.access_token);
  }
}

/**
 * QQ Token 响应容器
 */
class QQTokens {
  #accessToken;

  constructor(accessToken) {
    this.#accessToken = accessToken;
  }

  accessToken() {
    return this.#accessToken;
  }
}
