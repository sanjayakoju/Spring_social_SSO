import {Component, OnInit, TemplateRef, ViewChild} from '@angular/core';
import {OAuth2Provider} from "../auth.model";
import {filter, Subject, takeUntil} from "rxjs";
import {ActivatedRoute, convertToParamMap, ParamMap, Params, Router} from "@angular/router";
import {AuthenticationService} from "../../service/authentication.service";
import {QueryParamKey, QueryParamUIKey} from "../../constant/core.constant";
import {FormGroup} from "@angular/forms";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  protected readonly OAuth2Provider = OAuth2Provider;

  // page state
  loading: boolean = false;
  hasError: boolean = false;
  loginResponseMessage: string | null = null;
  resetPasswordResponseMessage: string | null = null;
  hasResetPasswordError: boolean = false;
  originalRequestedUri: string | null = null;

  // Form state
  loginForm!: FormGroup;
  isRememberMeChecked: boolean = false;
  isSubmitted = false;

  @ViewChild('passwordResetContent', { read: TemplateRef, static: true }) passwordResetContent!: TemplateRef<any>;
  emailAddressToResetPassword!: string;

  routeQueryParams: Params = {};

  private unsubscribe = new Subject<void>();

  constructor(private router: Router,
              private route: ActivatedRoute,
              private authenticationService: AuthenticationService) {
  }

  ngOnInit(): void {
    this.processRouteQueryParams();
  }
  onOAuth2SocialButtonClick(oauth2Provider: OAuth2Provider) {
    this.authenticationService.onOAuth2ButtonClick(oauth2Provider, this.routeQueryParams);
  }

  private processRouteQueryParams(): void {
    this.authenticationService.processAuthQueryParams()
      .pipe(
        filter((val: Params) => val && Object.keys(val).length > 0),
        takeUntil(this.unsubscribe)
      )
      .subscribe((params: Params) => {
        this.routeQueryParams = params;
        console.log('Login page routeQueryParams', this.routeQueryParams);
        const paramMap: ParamMap = convertToParamMap(params);
        this.originalRequestedUri = paramMap.get(QueryParamKey.ORIGINAL_REQUEST_URI)
        this.populateParamResponseMessage(paramMap, QueryParamKey.ERROR);
        this.populateParamResponseMessage(paramMap, QueryParamUIKey.REGISTRATION_SUCCESSFUL);
        this.populateParamResponseMessage(paramMap, QueryParamUIKey.PASSWORD_RESET_SUCCESSFUL);
      });
  }

  populateParamResponseMessage(paramMap: ParamMap, paramKey: string, isErrorType: boolean = false) {
    debugger
    if (paramMap.has(paramKey)) {
      const infoMsg = paramMap.get(paramKey);
      this.hasError = isErrorType ? true : false;
      this.loginResponseMessage = infoMsg && infoMsg.length > 0 ? infoMsg : null;
    }
  }

  ngOnDestroy(): void {
    this.unsubscribe.next();
    this.unsubscribe.complete();
  }
}
