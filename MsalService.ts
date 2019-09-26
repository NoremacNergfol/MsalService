import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { filter, take } from 'rxjs/operators';
import { ApiService } from '../ApiService/ApiService';
import { LocalStorageService } from '../LocalStorage/LocalStorageService';

declare var azureClientId;
declare var azureTenantId;

declare var dynamicsCRMTenantId;

const dynamicsCrmScopes: string[] = ["https://" + dynamicsCRMTenantId + "/.default", "openid", "offline_access"];

@Injectable()
export class MsalService {

  private _user: IUser;

  constructor(private localStorageService: LocalStorageService,
    private httpClient: HttpClient,
    private apiService: ApiService) {
  }

  get user(): IUser {
    return this._getUser();
  }

  get hasUser(): boolean {
    return !!this.user;
  }

  public processAuthorizationCallback(): IAuthorizationCallback {
    if (window.location.hash && window.location.hash.length > 1) {
      let hash: string[] = window.location.hash.substring(1).split("&");

      let authorizationCallback: IAuthorizationCallback = this.buildAuthorizationCallback(hash);

      return authorizationCallback;
    }

    return {};
  }

  private buildAuthorizationCallback(hash: string[]): IAuthorizationCallback {
    return {
      code: this.findSegment(hash, "code"),
      error: this.findSegment(hash, "error"),
      error_description: this.findSegment(hash, "error_description"),
      state: this.findSegment(hash, "state")
    }
  }

  private findSegment(hash: string[], segment: string): string {
    let match: string = hash.find((value: string) => { return value.startsWith(segment + "=") });

    if (match) {
      return match.substring((segment + "=").length);
    }

    return null;
  }

  public login(): void {
    let url: string = `https://login.microsoftonline.com/${azureTenantId}/oauth2/v2.0/authorize?`;

    let params: string[] = [
      `client_id=${azureClientId}`,
      `response_type=code`,
      `response_mode=fragment`,
      `scope=${this.getScopes()}`,
      `redirect_uri=${this.getRedirectUrl()}`
    ]

    window.location.replace(url + params.join("&"));
  }

  public logout(userRequested?: boolean): void {
    this.clearCache();
    if (userRequested) {
      window.location.replace(`https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=${this.getRedirectUrl()}`);
    }
  }

  public cacheAuthentication(json: any): void {
    this.localStorageService.setItem(this.accessToken, json.access_token);
    this.localStorageService.setItem(this.expiresIn, (this.getUnixTime() + json.expires_in - 1).toString());
    this.localStorageService.setItem(this.refreshToken, json.refresh_token);
    this._user = null;
  }

  private getUnixTime(): number {
    return (new Date().getTime() / 1000);
  }

  private get accessToken(): string {
    return "access_token_mvgo_";
  }

  private get expiresIn(): string {
    return "expires_in_mvgo_";
  }

  private get refreshToken(): string {
    return "refresh_token_mvgo_";
  }

  public acquireToken(resourceUri: string, tokenCallback: ITokenCallback): void {
    // resourceUri not currently used.
    // MSAL supports multiple tokens for multiple different resources.
    // Multiple resource support has not been implemented.
    this.refreshAccessToken().then((token: any) => {
      tokenCallback(token, null);
    }).catch((error) => {
      tokenCallback(null, error);
    })
  }

  private tokenSubject: BehaviorSubject<string> = new BehaviorSubject(null);
  private isRefreshingToken: boolean;

  private refreshAccessToken(): Promise<any> {
    let promise: Promise<any> = new Promise<any>((resolve, reject) => {
      try {
        let token: string = this.localStorageService.getItem(this.accessToken);
        let expiration: number = parseInt(this.localStorageService.getItem(this.expiresIn));
        if (this.getUnixTime() >= expiration || isNaN(expiration) || !token) {
          if (!this.isRefreshingToken) {
            this.isRefreshingToken = true;

            try {
              this.tokenSubject.next(null);

              let refreshToken: string = this.localStorageService.getItem(this.refreshToken);

              if (refreshToken) {
                this.httpClient.post(this.apiService.uri + "/api/Auth/RefreshToken", {
                  authorizationCode: refreshToken,
                }).subscribe(
                  (json: any) => {
                    this.isRefreshingToken = false;
                    this.cacheAuthentication(json);
                    this.tokenSubject.next(json.access_token);
                    resolve(json.access_token);
                  },
                  (error: any) => {
                    this.isRefreshingToken = false;
                    reject(error);
                  });
              } else {
                this.isRefreshingToken = false;
                reject("No refresh token found");
              }
            } catch (error) {
              this.isRefreshingToken = false;
              reject(error);
            }

          } else {
            try {
              this.tokenSubject.pipe(filter(token => token != null)).pipe(take(1)).subscribe(
                (token: any) => {
                  resolve(token);
                },
                (error: any) => {
                  reject(error);
                });
            } catch (error) {
              reject(error);
            }
          }
        } else if (token) {
          resolve(token);
        }
      } catch (error) {
        reject(error);
      }
    });

    return promise;
  }

  public clearCache(): void {
    this.localStorageService.removeItem(this.accessToken);
    this.localStorageService.removeItem(this.expiresIn);
    this.localStorageService.removeItem(this.refreshToken);
    this._user = null;
  }

  public getRedirectUrl(): string {
    let url: string = window.location.href;
    let hashIndex: number = window.location.hash ? url.indexOf(window.location.hash) : -1;

    url = ((hashIndex >= 0 ? url.substr(0, hashIndex) : url) + "#/login/");

    if (window.location.host !== "localhost") {
      url = url.replace("http:", "https:")
    }

    return encodeURI(url);
  }

  public getScopes(): string {
    return encodeURI(dynamicsCrmScopes.join(' '));
  }

  private _getUser(): IUser {
    var rawIdToken = this.localStorageService.getItem(this.accessToken);

    if (rawIdToken) {

      if (this._user) {
        return this._user;
      }

      let decodedToken: any = this.decodeJwt(rawIdToken);

      try {
        var base64IdToken = decodedToken.JWSPayload;
        var base64Decoded = this.base64DecodeStringUrlSafe(base64IdToken);
        if (!base64Decoded) {
          return null;
        }

        let tokenJson = JSON.parse(base64Decoded);

        let user: IUser = {
          name: tokenJson.name,
          userIdentifier: tokenJson.upn
        };

        this._user = user;
        return this._user;
      }
      finally {

      }
    }

    return null;
  }

  private base64DecodeStringUrlSafe(base64IdToken: string): string {
    base64IdToken = base64IdToken.replace(/-/g, "+").replace(/_/g, "/");
    if (window.atob) {
      return decodeURIComponent(encodeURIComponent(window.atob(base64IdToken)));
    }
    else {
      return decodeURIComponent(encodeURIComponent(this.decode(base64IdToken)));
    }
  }

  private decode(base64IdToken: string): string {
    var codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    base64IdToken = String(base64IdToken).replace(/=+$/, "");
    var length = base64IdToken.length;
    if (length % 4 === 1) {
      throw new Error("The token to be decoded is not correctly encoded.");
    }
    var h1, h2, h3, h4, bits, c1, c2, c3, decoded = "";
    for (var i = 0; i < length; i += 4) {
      //Every 4 base64 encoded character will be converted to 3 byte string, which is 24 bits
      // then 6 bits per base64 encoded character
      h1 = codes.indexOf(base64IdToken.charAt(i));
      h2 = codes.indexOf(base64IdToken.charAt(i + 1));
      h3 = codes.indexOf(base64IdToken.charAt(i + 2));
      h4 = codes.indexOf(base64IdToken.charAt(i + 3));
      // For padding, if last two are "="
      if (i + 2 === length - 1) {
        bits = h1 << 18 | h2 << 12 | h3 << 6;
        c1 = bits >> 16 & 255;
        c2 = bits >> 8 & 255;
        decoded += String.fromCharCode(c1, c2);
        break;
      }
      // if last one is "="
      else if (i + 1 === length - 1) {
        bits = h1 << 18 | h2 << 12;
        c1 = bits >> 16 & 255;
        decoded += String.fromCharCode(c1);
        break;
      }
      bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
      // then convert to 3 byte chars
      c1 = bits >> 16 & 255;
      c2 = bits >> 8 & 255;
      c3 = bits & 255;
      decoded += String.fromCharCode(c1, c2, c3);
    }
    return decoded;
  }

  private decodeJwt(jwtToken: string): any {
    var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;
    var matches = idTokenPartsRegex.exec(jwtToken);
    if (!matches || matches.length < 4) {
      //this._requestContext.logger.warn("The returned id_token is not parseable.");
      return null;
    }
    var crackedToken = {
      header: matches[1],
      JWSPayload: matches[2],
      JWSSig: matches[3]
    };
    return crackedToken;
  }
}

export interface ITokenCallback {
  (token: string, error: string): void;
};

export interface IUser {
  name: string;
  userIdentifier: string;
}

export interface IAuthorizationCallback {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}
