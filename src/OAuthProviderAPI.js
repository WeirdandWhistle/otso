import * as db from "./databaseInteraction.js";

// OAuth 2.0 endpoints
export async function authorize(request, env, KV){
    if(request.method != "GET")
        return new Response("400 Bad request. The appropriate HTTP method is 'GET'.", {status: 400});
    const query = request.url.searchParams;

    const client_id = query.get("client_id");
    const response_type = query.get("response_type");
    if(!client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!response_type){
        return new Response(`{"error":"invalid_request","error_description":"response_type must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }

    const OAuthClient = db.getOAuthClientFromClientID(env, client_id);
    if(!OAuthClient)
        return new Response(`{"error":"invalid_request","error_description":"404 Client does not exist. Check your client_id field."}`, {status: 404});

    let user = getUserIfSession(request, env);
    if(!user){
        // TODO: send to login/signup/authenticaton page
        return new Response("TODO: send to login/signup/authenticaton page");
    }
    const authorizedApps = user.authorizedApps.split(" ");
    let isAppAuthorized = false;
    for(const app of authorizedApps){
        if(app == client_id){
            isAppAuthorized = true;
            break;
        }
    }
    if(!isAppAuthorized){
        // TODO: send authorization page
        return new Response("TODO: send authorization page");
    }
    let redirect_uri = query.get("redirect_uri");
    let verifiyedRedirectURI = false;
    const redirectionURIs = OAuthClient.redirection_URIs.split(" ");

    if(redirectionURIs.length == 1){
        if(!redirect_uri)
            return new Response(`{"error":"invalid_request","error_description":"redirect_uri is incorrect. Must have one valid redirect_uri. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
        verifiyedRedirectURI = true;
        redirect_uri = redirectionURIs[0];
    } else if(!verifiyedRedirectURI && redirectionURIs.length > 1){
        for(const uri of redirectionURIs){
            if(uri == redirect_uri){
                verifiyedRedirectURI;
                break;
            }
        }
    }
    if(!verifiyedRedirectURI)
        return new Response(`{"error":"server_error","error_description":"Sorry, the server ran into an unexpected edge case. Please contact an admin"}`,{status:500});

    const scopes = query.get("scope").split(" ");
    if(scopes.length == 0)
        return new Response(`{"error":"invalid_scope","error_description":"Scope can not be nothing."}`,{status:500});



    if(response_type == "code"){
        const code = generateSecureChars(42);
        const redirectState = query.get("state");

        KV.put(`OAuthCode.${code}`, {client: client, user: user, redirect_uri: redirect_uri});

        const redirectTo = new URL(redirect_uri);
        redirectTo.searchParams.set("code", code);
        redirectTo.searchParams.set("state", redirectState);

        const goingTo = redirectTo.toString();
        return new Response(`You are currently being redirected to ${goingTo}.`,{
            status: 302,
            headers: {
                'Location' : goingTo
            }
        });
    } else if(response_type == "token"){
        return new Response("Implict OAuth is not currntly supported. Please submit an issue to the github.",{status: 400});
    } else {
        return new Response("Sorry, that response_type is not currently supported. Try either 'code' or 'token'.", {status: 404});
    }
}
export async function token(request, env, KV){
    if(request.method != "POST")
        return new Response("400 Bad request. The appropriate HTTP method is 'POST'.", {status: 400});
    const query = new URLSearchParams(await request.text());

    const code = query.get("code");
    const stateJson = KV.get(`OAuthCode.${code}`);
    const redirect_uri = query.get("redirect_uri");
    const grant_type = query.get("grant_type");
    if(!code){
        return new Response(`{"error":"invalid_request","error_description":"code must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!stateJson){
        return new Response(`{"error":"invalid_request","error_description":"code has been used, expired, or never existed."}`, {status: 400});
    } if(redirect_uri != stateJson.redirect_uri){
        return new Response(`{"error":"invalid_request","error_description":"redirect_uri must equal the one used to get the 'code'. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(grant_type != "authorization_code"){
        return new Response(`{"error":"invalid_request","error_description":"grant_type must be 'authorization_code'. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }
    KV.remove(`OAuthCode.${code}`);

    let client_id;
    let client_secret;

    if(request.header.get("Authorization")){
        const authArray = request.header.get("Authorization").split(" ");
        const tokenType = authArray[0];
        if(tokenType.toLowerCase != 'basic')
            return new Response(`{"error":"invalid_client","error_description":"When using HTTP Authorization you MUST use the 'Basic' token type. (eg, 'Basic 123xyz')) as defined Here: https://datatracker.ietf.org/doc/html/rfc2617#section-2"}`,{status: 401});
        const decodedBase64Array = window.atob(authArray[1]).split(":");
        client_id = decodedBase64Array[0];
        client_secret = decodedBase64Array[1];
    } else {
        client_id = query.get("client_id");
        client_secret = query.get("client_secret");
    }

    const response_type = query.get("response_type");
    if(!client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(!client_secret){
        return new Response(`{"error":"invalid_client","error_description":"client_secret must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    } if(client_id != stateJson.client.client_id){
        return new Response(`{"error":"invalid_client","error_description":"client_id used to gain 'code' must be the same as the one exchangeing for an access_token."}`, {status: 400});
    } if(!crypto.timingSafeEqual(client_secret, stateJson.client.client_secret)){
        return new Response(`{"error":"invalid_client","error_description":"client_secret is incorrect"}`, {status: 401});
    } if(!response_type){
        return new Response(`{"error":"invalid_request","error_description":"response_type must be present. OAuth 2.0 spec: https://datatracker.ietf.org/doc/html/rfc6749"}`, {status: 400});
    }



}
function issueAccessToken(env, userID, client_id, scopes, ttl){

}
// if request has valid session then get the user profile ELSE null
function getUserIfSession(request, env){
    const cookiesArray = request.header.get("Cookie").split(";");
    let sessionID;
    for(const cookie of cookiesArray){
        if(cookie.split("=")[0] == "sessionID")
            sessionID = cookie.split("=")[1];
    }
    if(!sessionID)
        return null;
    const userID = await db.getUserIDFromSession(env, sessionID);
    if(!userID)
        return null;
    return await db.getUserFromUserID(env, userID);
}

const generateSecureChars = (length) => {
	const buf = new Uint8Array(length+1);
	crypto.getRandomValues(buf);
	return buf.toBase64({alphabet: "base64url", omitPadding: true}).substing(0,length-1);
};