import { Injectable } from '@angular/core';
import {JwtTokenPayload, OAuth2Provider} from "../component/auth.model";
import {HttpClient} from "@angular/common/http";
import {ActivatedRoute, convertToParamMap, ParamMap, Params, Router} from "@angular/router";
import {ApiEndpoints} from "../constant/app-url.constant";
import {filter, map, Observable} from "rxjs";
import {QueryParamKey} from "../constant/core.constant";
import {Credentials, CredentialService} from "./credential.service";


@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

  readonly AUTH_URL = ApiEndpoints.AUTH;
  constructor(private router: Router,
              private route: ActivatedRoute,
              private http: HttpClient,
              private credentialService: CredentialService) { }

  onOAuth2ButtonClick(oauth2Provider: any, routeQueryParams: any) {
    console.log('appending routeQueryParams', routeQueryParams);
    const queryString = Object.entries(routeQueryParams)
      .map(entry => entry.join('='))
      .join('&');
    const appendQueryParams = queryString ? `&${queryString}` : '';
    let oauth2ProviderUrl: string = ''
    switch (oauth2Provider) {
      case OAuth2Provider.GOOGLE:
        oauth2ProviderUrl = this.AUTH_URL.GOOGLE_AUTH + appendQueryParams;
        break;
      case OAuth2Provider.FACEBOOK:
        oauth2ProviderUrl = this.AUTH_URL.FACEBOOK_AUTH + appendQueryParams;
        break;
      case OAuth2Provider.GITHUB:
        oauth2ProviderUrl = this.AUTH_URL.GITHUB_AUTH + appendQueryParams;
        break
      default:
        console.log('Incorrect oauth2Provider');
        break;
    }

    if (oauth2ProviderUrl && oauth2ProviderUrl.length > 0) {
      console.log('Hitting MyApp-Backend-Service - Outh2 authentication endpoint ', oauth2ProviderUrl);
      // TODO check with iframe too
      const windowTarget: string = '_self';
      window.open(oauth2ProviderUrl, windowTarget);
    }
  }

  public processAuthQueryParams(allowAuthRedirection: boolean = true): Observable<Params> {
    const processedQueryParamsObservable: Observable<Params> = this.route.queryParams
      .pipe(
        filter((params: Params) => params && Object.keys(params).length > 0),
        map((params: Params) => {
          const routeQueryParams: Params = { ...params }
          if (params && params.hasOwnProperty(QueryParamKey.TOKEN)) {
            const paramMap: ParamMap = convertToParamMap(routeQueryParams);
            if (paramMap.has(QueryParamKey.TOKEN)) {
              this.setOAuth2SuccessCredentials(paramMap, allowAuthRedirection);
              delete routeQueryParams[QueryParamKey.TOKEN];
            }
          }
          return routeQueryParams;
        })
      );
    return processedQueryParamsObservable;
  }

  private setOAuth2SuccessCredentials(resParamMap: ParamMap, redirectToOriginalUri?: boolean): boolean {
    console.log('Login Successful');
    const jwtToken = resParamMap.get('token') || '';
    const tokenPayload: JwtTokenPayload = this.parseJwt(jwtToken);
    const credentialsData: Credentials = {
      email: tokenPayload.email,
      token: jwtToken,
      jwtTokenPayload: tokenPayload
    };
    this.credentialService.setCredentials(credentialsData, false);
    if (redirectToOriginalUri) {
      const originalRequestedUri = resParamMap.get(QueryParamKey.ORIGINAL_REQUEST_URI)
      this.redirectToTargetRequestUri(originalRequestedUri);
    }
    return true;
  }

  private redirectToTargetRequestUri(targetRequestedUri?: string | null): void {
    debugger
    const targetUri = targetRequestedUri && targetRequestedUri.length > 0 ? targetRequestedUri : '/'
    console.log('Target URI ', targetUri)
    this.router.navigate(['/profile']);
  }

  // OPTIONAL: Parsing JWT Token to obtain extra-data
  private parseJwt(token: any): JwtTokenPayload {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('')
      .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));

    return JSON.parse(jsonPayload);
  };
}
