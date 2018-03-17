module Suave.OAuth

open Suave
open Suave.Cookie
open Suave.Operators
open Suave.Filters

type DataEnc = | FormEncode | JsonEncode | Plain

type ProviderConfig = {
    authorize_uri: string;
    exchange_token_uri: string;
    refresh_uri: string;
    client_id: string;
    client_secret: string
    request_info_uri: string
    scopes: string
    token_response_type: DataEnc
    customize_req: System.Net.HttpWebRequest -> unit
}

exception private OAuthException of string

/// <summary>
/// Result type for successive login callback.
/// </summary>
type LoginData = {ProviderName: string; Id: string; Name: string; Email:string; AccessToken: string; RefreshToken:string; ProviderData: Map<string,obj>}
type FailureData = {Code: int; Message: string; Info: obj}

let EmptyConfig =
    {authorize_uri = ""; exchange_token_uri = ""; request_info_uri = ""; refresh_uri=""; client_id = ""; client_secret = "";
    scopes = ""; token_response_type = FormEncode; customize_req = ignore}

/// <summary>
/// Default (incomplete) oauth provider settings.
/// </summary>
let private providerConfigs =
    Map.empty
    |> Map.add "google"
        {EmptyConfig with
            authorize_uri = "https://accounts.google.com/o/oauth2/v2/auth"
            exchange_token_uri = "https://www.googleapis.com/oauth2/v3/token"
            request_info_uri = "https://www.googleapis.com/oauth2/v1/userinfo"
            refresh_uri="https://www.googleapis.com/oauth2/v4/token"
            scopes = "profile"
            token_response_type = JsonEncode
            }
    |> Map.add "github"
        {EmptyConfig with
            authorize_uri = "https://github.com/login/oauth/authorize"
            exchange_token_uri = "https://github.com/login/oauth/access_token"
            request_info_uri = "https://api.github.com/user"
            refresh_uri=""
            scopes = ""}
    |> Map.add "facebook"
        {EmptyConfig with
            authorize_uri = "https://www.facebook.com/dialog/oauth"
            exchange_token_uri = "https://graph.facebook.com/oauth/access_token"
            request_info_uri = "https://graph.facebook.com/me"
            refresh_uri=""
            scopes = ""}

/// <summary>
/// Allows to completely define provider configs.
/// </summary>
/// <param name="f"></param>
let defineProviderConfigs f = providerConfigs |> Map.map f

module internal util =

    open System.Text
    open System.Web
    open System.Web.Script.Serialization

    let urlEncode = HttpUtility.UrlEncode:string->string
    let asciiEncode = Encoding.ASCII.GetBytes:string -> byte[]

    let formEncode = List.map (fun (k,v) -> String.concat "=" [k; urlEncode v]) >> String.concat "&"

    let formDecode (s:System.String) =
        s.Split('&') |> Seq.map(fun p -> let [|a;b|] = p.Split('=') in a,b) |> Map.ofSeq

    let parseJsObj js =
        let jss = new JavaScriptSerializer()
        jss.DeserializeObject(js) :?> seq<_> |> Seq.map (|KeyValue|) |> Map.ofSeq

module private impl =
    open Suave

    let getConfig ctx (configs: Map<string,ProviderConfig>) =

        let provider_key =
            match ctx.request.queryParam "provider" with
            |Choice1Of2 code -> code.ToLowerInvariant()
            | _ -> "google"

        match configs.TryFind provider_key with
        | None -> raise (OAuthException "bad provider key in query")
        | Some c -> provider_key, c

    let extractToken tokenType (config: ProviderConfig)=
        match config.token_response_type with
        | JsonEncode -> util.parseJsObj >> Map.tryFind tokenType >> Option.bind (unbox<string> >> Some)
        | FormEncode -> util.formDecode >> Map.tryFind tokenType >> Option.bind (unbox<string> >> Some)
        | Plain ->      Some

    let login (configs: Map<string,ProviderConfig>) redirectUri (fnSuccess: LoginData -> WebPart): WebPart =
        // TODO use Uri to properly add parameter to redirectUri
        (fun ctx ->
            let provider_key,config = configs |> getConfig ctx

            ctx.request.queryParam "code" |> printfn "param code: %A" // TODO log

            match ctx.request.queryParam "code" with
            | Choice2Of2 _ ->
                raise (OAuthException "server did not return access code")
            | Choice1Of2 code ->

                let parms =
                        [
                            "code", code
                            "client_id", config.client_id
                            "client_secret", config.client_secret
                            "redirect_uri", redirectUri + "?provider=" + provider_key
                            "grant_type", "authorization_code"
                        ]

                async {
                    let! response = parms |> util.formEncode |> util.asciiEncode |> HttpCli.post config.exchange_token_uri config.customize_req
                    response |> printfn "Auth response is %A"        // TODO log

                    let access_token = response |> extractToken "access_token" config
                    if Option.isNone access_token then
                        raise (OAuthException "failed to extract access token")

                    let refresh_token=response |> extractToken "refresh_token" config
                    if Option.isNone refresh_token then
                       raise (OAuthException "failed to extract access token")
  
                    let uri = config.request_info_uri + "?" + (["access_token", Option.get access_token] |> util.formEncode)
                    let! response = HttpCli.get uri config.customize_req
                    response |> printfn "/user response %A"        // TODO log

                    let mutable user_info:Map<string,obj> = response |> util.parseJsObj
                    
                    //save guid so that is able later to corelate client who requested access_token
                    let state=
                        match ctx.request.queryParam "state" with
                        | Choice1Of2 s -> s
                        | _ -> ""
                    user_info <- user_info.Add("state",state)  
                    
                    
                    user_info |> printfn "/user_info response %A"  // TODO log

                    let user_id = user_info.["id"] |> System.Convert.ToString
                    let user_name = user_info.["name"] |> System.Convert.ToString
                    let user_email = user_info.["email"] |> System.Convert.ToString

                    return! fnSuccess
                        { ProviderName = provider_key;
                          Id = user_id; Name = user_name; AccessToken = Option.get access_token; RefreshToken=Option.get refresh_token;
                          Email=user_email; ProviderData = user_info} ctx
                }
        )

    let refresh (configs: Map<string,ProviderConfig>) (fnSuccess: LoginData -> WebPart) (fnFailure: FailureData -> WebPart) refresh_token : WebPart =
        (fun ctx ->
            async {
            try
                match refresh_token with
                | Choice2Of2 _ -> return! fnFailure {FailureData.Code = 1; Message = "No refresh_token provided!"; Info = "Error"} ctx
                | Choice1Of2 refresh_token when refresh_token="" -> return! fnFailure {FailureData.Code = 1; Message = "No refresh_token provided!"; Info = "Error"} ctx
                | Choice1Of2 refresh_token ->
                    let provider_key,config = configs |> getConfig ctx

                    let parms=
                            [
                                "client_id", config.client_id
                                "client_secret", config.client_secret
                                "grant_type", "refresh_token"
                                "refresh_token", refresh_token
                            ] 

                    let! response = parms |> util.formEncode |> util.asciiEncode |> HttpCli.post config.refresh_uri config.customize_req
                    response |> printfn "Auth response is %A"        // TODO log

                    let access_token = response |> extractToken "access_token" config
                    if Option.isNone access_token then
                        raise (OAuthException "failed to extract access token")

                    let uri = config.request_info_uri + "?" + (["access_token", Option.get access_token] |> util.formEncode)
                    let! response = HttpCli.get uri config.customize_req
                    response |> printfn "/user response %A"        // TODO log

                    let mutable user_info:Map<string,obj> = response |> util.parseJsObj
            
                    user_info |> printfn "/user_info response %A"  // TODO log

                    let user_id = user_info.["id"] |> System.Convert.ToString
                    let user_name = user_info.["name"] |> System.Convert.ToString
                    let user_email = user_info.["email"] |> System.Convert.ToString

                    return! fnSuccess
                        { ProviderName = provider_key;
                          Id = user_id; Name = user_name; AccessToken = Option.get access_token; RefreshToken=refresh_token;
                          Email=user_email; ProviderData = user_info} ctx
            with e -> return! fnFailure {FailureData.Code = 1; Message = e.Message; Info = e} ctx
            }
        )

/// <summary>
/// Login action handler (low-level API).
/// </summary>
/// <param name="configs"></param>
/// <param name="redirectUri"></param>
let redirectAuthQuery (configs:Map<string,ProviderConfig>) redirectUri state : WebPart =
    warbler (fun ctx ->

        let provider_key,config = configs |> impl.getConfig ctx

        let parms = [
            "scope", config.scopes
            "access_type", "offline"
            "client_id", config.client_id
            "redirect_uri", redirectUri + "?provider=" + provider_key
            "response_type", "code"
            "prompt", "consent"
            "state", state  //Rizz8   
            ]

        let q = config.authorize_uri + "?" + (parms |> util.formEncode)
        printfn "sending request: %A" q     // TODO convert to a log record
        Redirection.FOUND q
    )

/// <summary>
/// OAuth login provider handler (low-level API).
/// </summary>
/// <param name="configs"></param>
/// <param name="redirectUri"></param>
/// <param name="f_success"></param>
/// <param name="f_failure"></param>
let processLogin (configs: Map<string,ProviderConfig>) redirectUri (fnSuccess: LoginData -> WebPart) 
    (fnFailure: FailureData -> WebPart): WebPart =
    fun ctx ->
        async {
            try
                let! res=impl.login configs redirectUri fnSuccess ctx 
                return res
            //try return! impl.login configs redirectUri fnSuccess ctx 
            with
                | OAuthException e -> return! fnFailure {FailureData.Code = 1; Message = e; Info = e} ctx
                | e -> return! fnFailure {FailureData.Code = 1; Message = e.Message; Info = e} ctx
        }

/// <summary>
/// Gets the login callback URL by an HTTP request.
/// Provided for demo purposes as it cannot handle more complicated scenarios involving proxy, docker, azure etc.
/// </summary>
/// <param name="ctx"></param>
let buildLoginUrl (ctx:HttpContext) =
    let bb = new System.UriBuilder (ctx.request.url)
    bb.Host <- ctx.request.host
    bb.Path <- "oalogin"
    bb.Query <- ""
    bb.ToString()

/// <summary>
/// Handles OAuth authorization requests. Stores auth info in session cookie
/// </summary>
/// <param name="loginRedirectUri">Provide external URL to /oalogin handler.</param>
/// <param name="configs">OAuth configs</param>
/// <param name="fnLogin">Store login data and provide continuation webpart</param>
/// <param name="fnLogout">Handle logout request and provide continuation webpart</param>
/// <param name="fnFailure"></param>
let authorize loginRedirectUri configs fnLogin fnLogout fnFailure (getState: HttpContext->string)=
    choose [
        path "/oaquery" >=> GET >=> context(fun ctx -> redirectAuthQuery configs loginRedirectUri (getState ctx))
        path "/logout" >=> GET >=> 
            context(fun _ ->
                let cont = fnLogout()
                unsetPair Authentication.SessionAuthCookie >=> unsetPair Suave.State.CookieStateStore.StateCookie >=> cont
            )
        //Callback from Google (or other provider)
        path "/oalogin" >=> GET >=>
            context(fun ctx ->
                processLogin configs loginRedirectUri
                    (fnLogin >> (fun wpb -> Authentication.authenticated Cookie.CookieLife.Session false >=> wpb))
                    fnFailure
                )
        path "/oarefresh" >=> GET >=>  
              context(fun ctx ->
                           impl.refresh configs (fnLogin >> (fun wpb -> Authentication.authenticated Cookie.CookieLife.Session false >=> wpb)) 
                               fnFailure (ctx.request.queryParam "refresh_token"))
            ]

/// <summary>
/// Utility handler which verifies if current user is authenticated using session cookie.
/// </summary>
/// <param name="configs"></param>
/// <param name="protectedApi"></param>
/// <param name="fnFailure"></param>
let protectedPart protectedApi fnFailure:WebPart =
    Authentication.authenticate Cookie.CookieLife.Session false
        (fun () -> Choice2Of2 fnFailure)
        (fun _ ->  Choice2Of2 fnFailure)
        protectedApi
