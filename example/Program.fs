// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

open Suave
open Suave.Operators
open Suave.Filters
open Suave.Successful
open Suave.Web
open Suave.DotLiquid

open Suave.OAuth
open System.Collections.Generic
open System.Net
open System.Web
open System.Web.Script.Serialization

type AppModel =
    {
    mutable name: string
    mutable logged_id: string
    mutable logged_in: bool
    mutable provider: string
    mutable providers: string[]
    }

type User={ Access_token: string ; Refresh_token: string ; Email: string }

module private Config =

    open System.Web.Script.Serialization
    open System.Collections.Generic

    let KVf f (kv:KeyValuePair<string,_>) = (kv.Key, kv.Value |> f)
    let jso f (d:obj) = ((d :?> IDictionary<string,_>)) |> Seq.map (KVf f) |> Map.ofSeq
    let jss = new JavaScriptSerializer()

    let readConfig file =
        (System.Environment.GetEnvironmentVariable("USERPROFILE"), file)
        |> System.IO.Path.Combine
        |> System.IO.File.ReadAllText
        |> jss.DeserializeObject
        |> jso (jso unbox<string>)

[<EntryPoint>]
let main argv =

    let model = {
        name = "Alex"; logged_id = ""; logged_in = false
        provider = ""
        providers = [|"Google"; "GitHub"; "Facebook" |]
        }

    // Here I'm reading my personal API keys from file stored in my %HOME% folder. You will likely define you keys in code (see below).
    //let ocfg = Config.readConfig ".suave.oauth.config"

    //let oauthConfigs =
    //    defineProviderConfigs (fun pname c ->
    //        let key = pname.ToLowerInvariant()
    //        {c with
    //            client_id = ocfg.[key].["client_id"]
    //            client_secret = ocfg.[key].["client_secret"]}
    //    )
    //    // the following code adds "yandex" provider (for demo purposes)
    //    |> Map.add "yandex"
    //        {OAuth.EmptyConfig with
    //            authorize_uri = "https://oauth.yandex.ru/authorize"
    //            exchange_token_uri = "https://oauth.yandex.ru/token"
    //            request_info_uri = "https://login.yandex.ru/info"
    //            scopes = ""
    //            client_id = "xxxxxxxx"; client_secret = "dddddddd"}

  // you will go that way more likely
    let oauthConfigs =
        defineProviderConfigs (function
            | "google" -> fun c ->
                {c with
                    client_id = "406858885876-epvs0046oklpi1us2ebvpbj2jv8of01o.apps.googleusercontent.com"
                    client_secret = "QfgGlT2S_et9wjvEJBhF4OMZ"
                    scopes="profile email https://www.googleapis.com/auth/spreadsheets.readonly"}
            | "github" -> fun c ->
                {c with
                    client_id = "<xxxxxxxxxxxxxx>"
                    client_secret = "<xxxxxxxxxxxxxx>"}
            | _ -> id    // this application does not define secret keys for other oauth providers
        )

    let mapClientsTokens=new Dictionary<string,User>()

    let app =
        choose [
            path "/" >=> page "main.html" model

            warbler(fun ctx ->
                let authorizeRedirectUri = buildLoginUrl ctx in
                // Note: logon state for current user is stored in global variable, which is ok for demo purposes.
                // in your application you shoud store such kind of data to session data
                OAuth.authorize authorizeRedirectUri oauthConfigs
                    (fun loginData ->
                        model.logged_in <- true
                        model.logged_id <- sprintf "%s (name: %s)" loginData.Id loginData.Name

                        //If state is present this is the access_token flow (the complete Google Oauth2 flow)
                        //If the state is not present, this is the refresh_token flow
                        //----------------------------------------------------------------------------------------------
                        if loginData.ProviderData.ContainsKey("state") then 
                            let guid=loginData.ProviderData.Item("state")
                            if not (mapClientsTokens.ContainsKey(guid.ToString())) then 
                                mapClientsTokens.Add(guid.ToString(),{Access_token=loginData.AccessToken; Refresh_token=loginData.RefreshToken;
                                     Email=loginData.Email}) 
                            Redirection.FOUND "/"
                        else
                            let jss = new JavaScriptSerializer()
                            OK (jss.Serialize({Access_token=loginData.AccessToken; Refresh_token=loginData.RefreshToken;
                                     Email=loginData.Email})) 
                    )
                    (fun () ->

                        model.logged_id <- ""
                        model.logged_in <- false
                        printfn "Logged Out!"
                        Redirection.FOUND "/"
                    )
                    (fun error -> OK <| sprintf "Authorization failed because of `%s`" error.Message)
                    (fun ctx -> match ctx.request.queryParam "GetToken" with
                                | Choice1Of2 p -> p
                                | _ -> "")
                )

            path "/GetToken" >=> context(fun ctx ->
                match ctx.request.queryParam("GetToken") with
                | Choice1Of2 p -> printfn "Receive request for token (GetToken) for Guid=%s" p
                                  let jss = new JavaScriptSerializer()
                                  if mapClientsTokens.ContainsKey(p) then 
                                    printfn "Token %s found" p
                                    let user=mapClientsTokens.Item(p)
                                    mapClientsTokens.Remove(p) |> ignore
                                    OK(jss.Serialize(user)) >=> Authentication.authenticated Cookie.CookieLife.Session false
                                  else
                                    printfn "Token %s NOT found" p
                                    Suave.RequestErrors.NOT_FOUND(sprintf "GetToken for %s not found" p)
                | Choice2Of2 e -> printfn "ERROR %s!!!!" e
                                  Suave.RequestErrors.BAD_REQUEST "GetToken: Request Unknow!!")  

            OAuth.protectedPart
                (choose [
                    path "/protected" >=> GET >=> OK "You've accessed protected part!"
                ])
                (RequestErrors.FORBIDDEN "You do not have access to that application part (/protected)")

            // we'll never get here
            (OK "Hello World!")
        ]

    let serverConfig={defaultConfig  with bindings=[HttpBinding.create HTTP IPAddress.Loopback (uint16 8083)]}
    startWebServer serverConfig app
    0
